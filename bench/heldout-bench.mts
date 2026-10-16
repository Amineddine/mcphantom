/**
 * Phase 7 fresh held-out poisoned set — run ONCE (bench/corpus/heldout-7/PREREGISTRATION.md).
 *
 *   npm run bench:heldout              # verifies MANIFEST.sha256, runs, writes bench/results/heldout-7.*
 *   npm run bench:heldout -- --verify  # manifest check only (no scanner run)
 *
 * "Caught" = the tool is hidden at default settings: `scanTool` flagged at `block: medium` (the gateway
 * also hides a tool whose inspection throws — counted as caught and marked). Reported with Wilson 95%
 * intervals in three separate groups that are never pooled: the claimed headline set, the MSB
 * prompt-injection subgroup whose placement was reconstructed from MSB's disabled insertion code
 * (amendment 1), and the kinds outside the claims. Every miss and every exclusion is listed.
 * Refuses to run if a result already exists: the set is run once, and a fix found from it needs new
 * dev examples first.
 */
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { scanTool } from '../src/scanner/scan.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const setDir = path.join(here, 'corpus', 'heldout-7');
const resultMd = path.join(here, 'results', 'heldout-7.md');
const resultJson = path.join(here, 'results', 'heldout-7.json');

// ---- manifest ----------------------------------------------------------------------------------------
function verifyManifest(): string {
  const manifest = fs.readFileSync(path.join(setDir, 'MANIFEST.sha256'), 'utf8');
  const listed = new Map<string, string>();
  for (const line of manifest.split('\n').filter(Boolean)) {
    const m = /^(?<hash>[0-9a-f]{64}) {2}(?<file>.+)$/.exec(line);
    if (!m?.groups?.hash || !m.groups.file) throw new Error(`malformed manifest line: ${line}`);
    listed.set(m.groups.file, m.groups.hash);
  }
  const onDisk: string[] = [];
  const walk = (d: string) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else onDisk.push(path.relative(setDir, p).split(path.sep).join('/'));
    }
  };
  walk(setDir);
  const problems: string[] = [];
  for (const rel of onDisk.filter((f) => f !== 'MANIFEST.sha256')) {
    const want = listed.get(rel);
    const got = crypto.createHash('sha256').update(fs.readFileSync(path.join(setDir, rel))).digest('hex');
    if (!want) problems.push(`not in manifest: ${rel}`);
    else if (want !== got) problems.push(`hash mismatch: ${rel}`);
  }
  for (const rel of listed.keys()) if (!onDisk.includes(rel)) problems.push(`missing: ${rel}`);
  if (problems.length) throw new Error(`MANIFEST.sha256 does not match the set:\n  ${problems.join('\n  ')}`);
  return crypto.createHash('sha256').update(manifest).digest('hex');
}

// ---- Wilson score interval (95%) ----------------------------------------------------------------------
const Z = 1.959963984540054;
export function wilson(k: number, n: number): [number, number] {
  if (n === 0) return [NaN, NaN];
  const p = k / n;
  const d = 1 + (Z * Z) / n;
  const c = (p + (Z * Z) / (2 * n)) / d;
  const h = (Z * Math.sqrt((p * (1 - p)) / n + (Z * Z) / (4 * n * n))) / d;
  return [Math.max(0, c - h), Math.min(1, c + h)];
}
// Known values (e.g. Newcombe 1998 / any Wilson table) — the run refuses to start if these drift.
for (const [k, n, lo, hi] of [[0, 4, 0, 0.4899], [4, 4, 0.5101, 1], [5, 10, 0.2366, 0.7634], [81, 263, 0.2553, 0.3662]] as const) {
  const [l, h] = wilson(k, n);
  if (Math.abs(l - lo) > 1e-4 || Math.abs(h - hi) > 1e-4) throw new Error(`wilson(${k}, ${n}) self-check failed: ${l}, ${h}`);
}

// ---- run ---------------------------------------------------------------------------------------------
interface Item { id: string; source: string; kind: string; claimed: boolean; subgroup: 'main' | 'msb-pi-reconstructed'; oos_param?: string[]; tool: Tool }
interface HeldOut { items: Item[]; excluded: { source: string; name: string; why: string }[]; not_extracted: { source: string; why: string }[]; overlaps_with_dev_test: { source: string; name: string; overlap: string[] }[]; notes: string[]; sources: { repo: string; commit: string }[] }

const manifestSha = verifyManifest();
if (process.argv.includes('--verify')) {
  process.stdout.write(`MANIFEST.sha256 verified (sha256 of manifest ${manifestSha}).\n`);
  process.exit(0);
}
if (fs.existsSync(resultJson)) {
  process.stderr.write(`${path.relative(process.cwd(), resultJson)} exists: this set is run once. Not running again.\n`);
  process.exit(1);
}

const set = JSON.parse(fs.readFileSync(path.join(setDir, 'heldout.json'), 'utf8')) as HeldOut;
const outcomes = set.items.map((it) => {
  try {
    const r = scanTool(it.tool);
    return { ...it, caught: r.flagged, threw: false, worst: r.worst ?? null, findings: r.findings.map((f) => `${f.severity} ${f.category} @${f.where}: ${f.detail}`) };
  } catch (e) {
    return { ...it, caught: true, threw: true, worst: null, findings: [`inspection threw (gateway hides fail-closed): ${(e as Error).message}`] };
  }
});

type O = (typeof outcomes)[number];
const pct = (x: number) => (Number.isNaN(x) ? 'n/a' : `${(x * 100).toFixed(1)}%`);
function table(rows: O[]): string[] {
  const kinds = [...new Set(rows.map((r) => r.kind))].sort();
  const line = (label: string, rs: O[]) => {
    const k = rs.filter((r) => r.caught).length;
    const [lo, hi] = wilson(k, rs.length);
    return `| ${label} | ${k} / ${rs.length} | ${pct(k / rs.length)} | ${pct(lo)} – ${pct(hi)} |`;
  };
  return ['| kind | caught / total | rate | Wilson 95% CI |', '|---|---|---|---|', ...kinds.map((kd) => line(kd, rows.filter((r) => r.kind === kd))), line('**all in this group**', rows)];
}

const headline = outcomes.filter((o) => o.claimed && o.subgroup === 'main');
const msbPi = outcomes.filter((o) => o.subgroup === 'msb-pi-reconstructed');
const outside = outcomes.filter((o) => !o.claimed);
const misses = outcomes.filter((o) => !o.caught);
const scannerCommit = (() => {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: here, encoding: 'utf8' }).trim();
  } catch {
    return 'unknown';
  }
})();
const env = { date: new Date().toISOString(), node: process.version, os: `${os.type()} ${os.release()}`, scannerCommit, manifestSha256: manifestSha };

const lines = [
  '# Phase 7 fresh held-out poisoned set — the one run',
  '',
  `Run ${env.date} · scanner at commit \`${scannerCommit}\` · default settings (\`scan.block: medium\`, hide) · ${env.node} · ${env.os}.`,
  `MANIFEST.sha256 verified before the run (sha256 of the manifest: \`${manifestSha}\`). Rules: \`bench/corpus/heldout-7/PREREGISTRATION.md\` (with amendment 1).`,
  `Sources: ${set.sources.map((s) => `${s.repo}@${s.commit.slice(0, 7)}`).join(', ')}. "Caught" = hidden at default settings.`,
  '',
  '## 1. Claimed — headline',
  '',
  ...table(headline),
  '',
  '## 2. Claimed kinds — MSB PI, placement reconstructed from MSB\'s disabled insertion code (not pooled)',
  '',
  'MSB\'s active harness (at c1d6a70) appends the injection to the system prompt, not to a tool definition; these',
  'items place MSB\'s template and goals where its commented-out code would have. The "parameter description"',
  'items carry the text inside `description` (FastMCP keeps the `Args:` section there), not in `inputSchema`.',
  '',
  ...table(msbPi),
  '',
  '## 3. Outside the claims (reported, not claimed)',
  '',
  ...table(outside),
  '',
  `## Every miss (${misses.length})`,
  '',
  ...(misses.length ? misses.map((m) => `- \`${m.id}\` ${m.claimed ? '**claimed**' : 'outside claims'} · ${m.kind} · \`${m.tool.name}\` · ${m.source}${m.findings.length ? ` · below threshold: ${m.findings.join('; ')}` : ''}`) : ['None.']),
  '',
  '## Catches in the claimed groups',
  '',
  ...outcomes.filter((o) => o.claimed && o.caught).map((o) => `- \`${o.id}\` ${o.kind} · \`${o.tool.name}\` · ${o.findings[0] ?? ''}`),
  '',
  '## Catches outside the claims',
  '',
  ...outside.filter((o) => o.caught).map((o) => `- \`${o.id}\` ${o.kind} · \`${o.tool.name}\` · ${o.findings[0] ?? ''}`),
  '',
  `## Exclusions (${set.excluded.length}), not extracted (${set.not_extracted.length}), overlaps with dev/test (${set.overlaps_with_dev_test.length})`,
  '',
  ...set.excluded.map((e) => `- excluded · \`${e.name}\` · ${e.source} · ${e.why}`),
  ...set.not_extracted.map((e) => `- not extracted · ${e.source} · ${e.why}`),
  ...set.overlaps_with_dev_test.map((e) => `- overlap · \`${e.name}\` · ${e.source} · ${e.overlap.join('; ')}`),
  '',
  '## Notes from extraction',
  '',
  ...set.notes.map((n) => `- ${n}`),
  '',
];
fs.mkdirSync(path.dirname(resultMd), { recursive: true });
fs.writeFileSync(resultJson, JSON.stringify({ env, outcomes: outcomes.map(({ tool, ...o }) => ({ ...o, name: tool.name })) }, null, 1) + '\n');
fs.writeFileSync(resultMd, lines.join('\n'));
process.stdout.write(lines.join('\n'));
