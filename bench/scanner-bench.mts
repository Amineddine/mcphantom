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
  // Phase 6b: real first-party definitions (bench/corpus/import-benign-thirdparty.mjs; licences in NOTICE).
  ...load('benign-github.json'),
  ...load('benign-playwright.json'),
  // Round 5t: author-written DEV-split tuning examples (bench/corpus/build-tuning-dev.mjs).
  ...load('benign-dev-tuning.json'),
  // 6b PR 6: author-written DEV-split self-reference examples (bench/corpus/build-tuning-dev-r6.mjs).
  ...load('benign-dev-shadow-self.json'),
  // Benign shapes that once caused false positives (AUD-6); kept so the regression stays measured.
  ...load('benign-regressions.json'),
  ...load('malicious.json'),
  // Phase 6b: rewritten from published third-party research, held-out TEST split only (never tuned on).
  ...load('malicious-thirdparty.json'),
  ...load('malicious-schema-dev.json'),
  ...load('malicious-shadow-dev.json'),
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
const dev = tally(devSet);
// `--dev`: the only view used while tuning — the held-out split is not even evaluated.
if (process.argv.includes('--dev')) {
  const d = rates(dev.counts);
  process.stdout.write(`dev split: ${dev.counts.tp + dev.counts.fn} malicious, ${dev.counts.fp + dev.counts.tn} benign; TPR ${pct(d.tpr)}, FPR ${pct(d.fpr)}\n`);
  for (const s of dev.falseNegatives) process.stdout.write(`  FN ${s}\n`);
  for (const s of dev.falsePositives) process.stdout.write(`  FP ${s}\n`);
  process.exit(0);
}
const test = tally(testSet);
const all = tally(items);

const benignTotal = items.filter((i) => i.label === 'benign').length;
const benignSynthetic = items.filter((i) => i.label === 'benign' && (i.source ?? '').startsWith('synthetic')).length;
// Author-written dev examples are not real definitions (5t printed them as real; fixed in 6b PR 6).
const benignAuthored = items.filter((i) => i.label === 'benign' && (i.source ?? '').startsWith('author-written')).length;
const malTotal = items.filter((i) => i.label === 'malicious').length;
const sources = [...new Set(items.filter((i) => i.label === 'benign' && !/^(?:synthetic|author-written)/.test(i.source ?? '')).map((i) => i.source))];

const r = (name: string, t: ReturnType<typeof tally>) => {
  const { tpr, fpr, precision } = rates(t.counts);
  return `| ${name} | ${t.counts.tp + t.counts.fn} | ${t.counts.fp + t.counts.tn} | ${pct(tpr)} | ${pct(fpr)} | ${pct(precision)} |`;
};

const lines = [
  '# Tier-1 static scanner benchmark',
  '',
  `Generated ${new Date().toISOString()} · scanner block threshold: medium.`,
  '',
  `Corpus: ${malTotal} malicious (synthetic, hand-labelled) + ${benignTotal} benign (${benignTotal - benignSynthetic - benignAuthored} real tool definitions, ${benignAuthored} author-written dev examples, ${benignSynthetic} synthetic false-positive regressions).`,
  `Benign sources: ${sources.join(', ')}.`,
  'Split is frozen: `test` is held out and never tuned against; detectors are tuned only on `dev`.',
  '',
  '| split | malicious | benign | TPR (recall) | FPR | precision |',
  '|---|---|---|---|---|---|',
  r('test (held-out)', test),
  r('dev', dev),
  r('all', all),
  '',
  '**Tuning round 5t (Phase 6b), before → after, held-out split:** TPR 91.7% (11/12) → 100% (12/12);',
  'FPR 0.8% (1/132) → 0% (0/132). Dev split: TPR 60.0% → 100%, FPR 3.1% → 0% (after adding 8 malicious',
  'full-schema-poisoning and 6 benign tool-routing examples, written before the change). Changes: every',
  'model-visible schema field is scanned (parameter names, `required`, unknown keywords, nested defaults),',
  'hints in structural fields count as medium, and "call this tool" is not read as a redirect to another',
  'tool. **The held-out split had already been observed before this round** (the full-schema-poisoning',
  'miss was seen in PR #5), so the after number is weaker evidence than the first held-out run. One rule',
  'was refined after that held-out run (values of unknown keywords count as structural), prompted by a new',
  'unit test, not by held-out data; the held-out numbers were unchanged by it.',
  '',
  '**6b PR 6 (tool-shadowing self-reference), before → after.** The shadowing rule read "this tool" and',
  '"the same tool" as the name of another tool — found on PostHog’s catalog (3 of its 5 hidden tools), not',
  'tuned on it. Dev split, after adding 6 benign self-reference and 3 shadowing examples written before the',
  'change: TPR 100% → 100% (18/18), FPR 4.5% (6/134) → 0%. Held-out (already observed, see above): 100% /',
  '0% before and after. PostHog catalog, reported only: hidden 5 → 2 of 1,121 (`npm run bench:posthog`).',
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
