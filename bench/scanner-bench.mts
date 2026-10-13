/**
 * Tier-1 static-scanner benchmark. Deterministic, no model, runs in CI.
 *
 *   npm run bench:scanner
 *
 * Corpus: real tool definitions from four official MCP servers (benign), plus a hand-labelled set of
 * synthetic poisoned tools (malicious). Each item has a frozen `split`: `dev` is for tuning detectors,
 * `test` is the held-out evaluation that is never tuned against. Benign split is assigned by a stable
 * hash of source+name so it does not drift between runs. Reported: TPR (recall), FPR, precision, and a
 * per-category breakdown, for the test split and overall.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanTool, type ScanResult } from '../src/scanner/scan.js';
import type { Tool } from '@modelcontextprotocol/sdk/types.js';

interface Item {
  source?: string;
  label: 'benign' | 'malicious';
  category?: string;
  split?: 'dev' | 'test';
  tool: Tool;
}

const here = path.dirname(fileURLToPath(import.meta.url));
const corpusDir = path.join(here, 'corpus');

function load(file: string): Item[] {
  return JSON.parse(fs.readFileSync(path.join(corpusDir, file), 'utf8')) as Item[];
}

function stableSplit(key: string): 'dev' | 'test' {
  // Even first hex nibble → test, odd → dev. Fixed forever for a given key.
  return parseInt(crypto.createHash('sha256').update(key).digest('hex')[0] ?? '0', 16) % 2 === 0 ? 'test' : 'dev';
}

const items: Item[] = [
  ...load('benign-fs.json'),
  ...load('benign-official.json'),
  // Benign shapes that once caused false positives (AUD-6); kept so the regression stays measured.
  ...load('benign-regressions.json'),
  ...load('malicious.json'),
].map((it) => ({ ...it, split: it.split ?? stableSplit(`${it.source ?? ''}|${it.tool.name}|${it.tool.description ?? ''}`) }));

interface Counts {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
}
const zero = (): Counts => ({ tp: 0, fp: 0, tn: 0, fn: 0 });

function tally(set: Item[]): { counts: Counts; byCategory: Record<string, { total: number; caught: number }>; falsePositives: string[]; falseNegatives: string[] } {
  const counts = zero();
  const byCategory: Record<string, { total: number; caught: number }> = {};
  const falsePositives: string[] = [];
  const falseNegatives: string[] = [];
  for (const it of set) {
    const r: ScanResult = scanTool(it.tool);
    if (it.label === 'malicious') {
      const cat = it.category ?? 'uncategorized';
      byCategory[cat] ??= { total: 0, caught: 0 };
      byCategory[cat].total++;
      if (r.flagged) {
        counts.tp++;
        byCategory[cat].caught++;
      } else {
        counts.fn++;
        falseNegatives.push(`${cat}: ${(it.tool.description ?? '').slice(0, 60)}`);
      }
    } else if (r.flagged) {
      counts.fp++;
      falsePositives.push(`${it.source ?? '?'} ${it.tool.name}: ${r.findings[0]?.detail ?? ''}`);
    } else {
      counts.tn++;
    }
  }
  return { counts, byCategory, falsePositives, falseNegatives };
}

function rates(c: Counts) {
  const tpr = c.tp + c.fn === 0 ? NaN : c.tp / (c.tp + c.fn);
  const fpr = c.fp + c.tn === 0 ? NaN : c.fp / (c.fp + c.tn);
  const precision = c.tp + c.fp === 0 ? NaN : c.tp / (c.tp + c.fp);
  return { tpr, fpr, precision };
}
const pct = (x: number) => (Number.isNaN(x) ? 'n/a' : `${(x * 100).toFixed(1)}%`);

const testSet = items.filter((i) => i.split === 'test');
const devSet = items.filter((i) => i.split === 'dev');
const test = tally(testSet);
const dev = tally(devSet);
const all = tally(items);

const benignTotal = items.filter((i) => i.label === 'benign').length;
const benignSynthetic = items.filter((i) => i.label === 'benign' && (i.source ?? '').startsWith('synthetic')).length;
const malTotal = items.filter((i) => i.label === 'malicious').length;
const sources = [...new Set(items.filter((i) => i.label === 'benign' && !(i.source ?? '').startsWith('synthetic')).map((i) => i.source))];

const r = (name: string, t: ReturnType<typeof tally>) => {
  const { tpr, fpr, precision } = rates(t.counts);
  return `| ${name} | ${t.counts.tp + t.counts.fn} | ${t.counts.fp + t.counts.tn} | ${pct(tpr)} | ${pct(fpr)} | ${pct(precision)} |`;
};

const lines = [
  '# Tier-1 static scanner benchmark',
  '',
  `Generated ${new Date().toISOString()} · scanner block threshold: medium.`,
  '',
  `Corpus: ${malTotal} malicious (synthetic, hand-labelled) + ${benignTotal} benign (${benignTotal - benignSynthetic} real tool definitions, ${benignSynthetic} synthetic false-positive regressions).`,
  `Benign sources: ${sources.join(', ')}.`,
  'Split is frozen: `test` is held out and never tuned against; detectors are tuned only on `dev`.',
  '',
  '| split | malicious | benign | TPR (recall) | FPR | precision |',
  '|---|---|---|---|---|---|',
  r('test (held-out)', test),
  r('dev', dev),
  r('all', all),
  '',
  '## Detection by category (all items)',
  '',
  '| category | caught / total |',
  '|---|---|',
  ...Object.entries(all.byCategory).map(([c, v]) => `| ${c} | ${v.caught} / ${v.total} |`),
  '',
];
if (all.falsePositives.length) {
  lines.push('## False positives (benign flagged) — every one listed', '', ...all.falsePositives.map((s) => `- ${s}`), '');
}
if (all.falseNegatives.length) {
  lines.push('## False negatives (malicious missed) — every one listed', '', ...all.falseNegatives.map((s) => `- ${s}`), '');
}
lines.push(
  'Caveat: this corpus is small and the malicious set is author-written, so these numbers bound nothing',
  'about novel attacks. They are a regression signal and a floor. The adversarial-evasion suite (Phase 6)',
  'and third-party payloads strengthen it.',
  '',
);
const md = lines.join('\n');
const env = { date: new Date().toISOString(), node: process.version, os: `${os.type()} ${os.release()}` };
fs.mkdirSync(path.join(here, 'results'), { recursive: true });
fs.writeFileSync(path.join(here, 'results', 'scanner-bench.md'), md);
fs.writeFileSync(path.join(here, 'results', 'scanner-bench.json'), JSON.stringify({ env, test: { ...test.counts, ...rates(test.counts) }, dev: { ...dev.counts, ...rates(dev.counts) }, all: { ...all.counts, ...rates(all.counts) }, byCategory: all.byCategory, falsePositives: all.falsePositives, falseNegatives: all.falseNegatives }, null, 2));
process.stdout.write(md);

// Exit non-zero if the held-out test split regresses below a floor, so CI catches detector rot.
const t = rates(test.counts);
if (!Number.isNaN(t.tpr) && t.tpr < 0.9) {
  process.stderr.write(`\nFAIL: test-split TPR ${pct(t.tpr)} below floor 90%\n`);
  process.exitCode = 1;
}
if (!Number.isNaN(t.fpr) && t.fpr > 0.1) {
  process.stderr.write(`\nFAIL: test-split FPR ${pct(t.fpr)} above ceiling 10%\n`);
  process.exitCode = 1;
}
