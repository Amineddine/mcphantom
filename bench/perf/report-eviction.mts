/**
 * Eviction-only report for a rerun (the R7p-3 fix, pre-registered in bench/perf/PREREGISTRATION-r7p3.md),
 * with a before/after table against the item-5 run. It reads raw files from `bench/results/<dir>/` and the
 * "before" eviction rows from `bench/results/perf/`, which it leaves as they are.
 *
 *   npx tsx bench/perf/report-eviction.mts perf-r7p3 eviction-r7p3.md
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadScenario } from '../attack/scenario.js';
import { rate } from '../attack/stats.js';
import { memoryPerTrace, report as evictionReport, ARMS, BUDGETS, type TraceRun } from './eviction.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const RESULTS = path.join(here, '..', 'results');
const [dir = 'perf-r7p3', outName = 'eviction-r7p3.md'] = process.argv.slice(2);

interface Raw { file: string; env: { runner: string; commit: string }; results: { eviction?: TraceRun[]; shard?: string; sets?: string[] } }
const read = (d: string): Raw[] => {
  const p = path.join(RESULTS, path.basename(d));
  if (!fs.existsSync(p)) return [];
  return fs.readdirSync(p).filter((f) => f.endsWith('.json')).sort()
    .map((f) => ({ file: `${path.basename(d)}/${f}`, ...(JSON.parse(fs.readFileSync(path.join(p, f), 'utf8')) as Omit<Raw, 'file'>) }))
    .filter((r) => Array.isArray(r.results.eviction));
};
const after = read(dir);
const before = read('perf');
if (after.length === 0) throw new Error(`no eviction raw files in bench/results/${dir}`);
const rowsAfter = after.flatMap((r) => r.results.eviction ?? []);
// A set can come from more than one file (laptop policy family, CI suite shards): never count a trace twice.
const seen = new Set<string>();
const dedup = rowsAfter.filter((r) => {
  const k = `${r.set}|${r.arm}|${String(r.budget)}|${r.id}`;
  if (seen.has(k)) return false;
  seen.add(k);
  return true;
});
const rowsBefore = before.flatMap((r) => r.results.eviction ?? []);

const load = (f: string) => (JSON.parse(fs.readFileSync(path.join(here, '..', 'attack', f), 'utf8')) as unknown[]).map(loadScenario);
const allSets = [
  { id: 'suite', title: 'Item-3 suite (83 traces, unchanged)', scenarios: load('scenarios.json') },
  { id: 'policy', title: 'Policy family (8 traces, unchanged)', scenarios: load('scenarios-policy.json') },
];
const present = new Set(dedup.map((r) => r.set));
const sets = allSets.filter((s) => present.has(s.id));

const partial = (r: TraceRun) => r.success === false && r.fragments.received > 0;
const cell = (rows: TraceRun[], set: string, arm: string, budget: number | null) => rows.filter((r) => r.set === set && r.arm === arm && r.budget === budget);
const summary = (cs: TraceRun[]) => {
  const atk = cs.filter((r) => r.kind === 'attack' && r.claimed);
  const ben = cs.filter((r) => r.kind === 'benign');
  return {
    success: rate(atk.filter((r) => r.success).length, atk.length),
    partial: rate(atk.filter(partial).length, atk.length),
    falseBlocks: rate(ben.filter((r) => !r.utility).length, ben.length),
    failClosed: cs.filter((r) => r.decisions.some((d) => d?.failClosed)).length,
  };
};

const L: string[] = [
  '# Eviction loss after the R7p-3 fix', '',
  'Rerun of Phase 7 item 5\'s eviction part (E) on the R7p-3 fix, pre-registered in `bench/perf/PREREGISTRATION-r7p3.md`.',
  'Deterministic decision-level replay, as before; the item-5 results (`bench/results/eviction.md`) are the "before".', '',
  `Source: ${after.map((r) => `\`bench/results/${r.file}\` (${(r.results.sets ?? ['suite', 'policy']).join(', ')}, ${r.results.shard ?? '1/1'}, ${r.env.runner}, commit \`${r.env.commit.slice(0, 7)}\`)`).join(', ')}.`, '',
  '| arm | what |', '|---|---|', ...ARMS.map((a) => `| ${a.id} | ${a.name} |`), '', `Budgets (MiB): ${BUDGETS.join(', ')}.`, '',
  '## Before → after', '',
  'Claimed attacks (success, partial leaks), benign traces (false blocks), Wilson 95%; fail-closed = traces with a `fail-closed` deny on their own steps.', '',
];
for (const set of sets) {
  L.push(`### ${set.title}`, '', '| arm | budget (MiB) | attack success | partial leaks | false blocks | fail-closed traces |', '|---|---|---|---|---|---|');
  for (const arm of ARMS.map((a) => a.id)) {
    for (const b of arm === 'F0' ? [null] : [...BUDGETS]) {
      const a = cell(dedup, set.id, arm, b);
      if (a.length === 0) continue;
      const x = summary(cell(rowsBefore, set.id, arm, b));
      const y = summary(a);
      const arrow = (p: string, q: string) => (p === q ? q : `${p} → **${q}**`);
      L.push(`| ${arm} | ${b ?? '—'} | ${arrow(x.success, y.success)} | ${arrow(x.partial, y.partial)} | ${arrow(x.falseBlocks, y.falseBlocks)} | ${arrow(String(x.failClosed), String(y.failClosed))} |`);
    }
  }
  L.push('');
}
const over = dedup.filter((r) => r.budget !== null && (r.maxIndexBytes ?? 0) > r.budget * 1024 * 1024);
L.push('## Index bound (Q-8)', '', `Traces where Tier A + Tier B + external bytes exceeded the budget after any ingest: ${String(over.length)} of ${String(dedup.filter((r) => r.budget !== null).length)}${over.length ? ` (${over.map((r) => `\`${r.id}\` ${r.arm} at ${String(r.budget)}`).join(', ')})` : ''}.`, '');
L.push('## Full tables (after)', '', ...evictionReport(dedup, sets));
L.push('## M1 — index size at the end of each trace (F0, defaults)', '', ...memoryPerTrace(dedup), '');
fs.writeFileSync(path.join(RESULTS, path.basename(outName)), `${L.join('\n')}\n`);
process.stdout.write(`wrote bench/results/${path.basename(outName)} from ${String(after.length)} raw file(s)\n`);
