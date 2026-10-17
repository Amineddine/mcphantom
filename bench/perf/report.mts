/**
 * Builds `bench/results/perf.md` and `bench/results/eviction.md` from the raw files in
 * `bench/results/perf/` (CI replicates `ci-<n>.json`, laptop `laptop-1.json`), with the statistics
 * pre-registered in bench/perf/PREREGISTRATION-perf.md.
 *
 *   npx tsx bench/perf/report.mts
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadScenario } from '../attack/scenario.js';
import { rate } from '../attack/stats.js';
import { memoryPerTrace, report as evictionReport, ARMS, BUDGETS, type TraceRun } from './eviction.js';
import { bootstrapDeltas, bootstrapQuantiles, BOOTSTRAP_B, BOOTSTRAP_SEED, median, spread, type Estimate, type Nested } from './stats.js';
import { SIZES } from './worker.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const RESULTS = path.join(here, '..', 'results');
const RAW = path.join(RESULTS, 'perf');

interface Env { env: string; replicate: number; date: string; commit: string; node: string; os: string; cpu: string; cores: number; memGb: number; power: string; runner: string; launches: number; set: string }
interface Raw { env: Env; results: Record<string, unknown> }
const files = fs.existsSync(RAW) ? fs.readdirSync(RAW).filter((f) => f.endsWith('.json')).sort() : [];
const raws = files.map((f) => ({ file: f, ...(JSON.parse(fs.readFileSync(path.join(RAW, f), 'utf8')) as Raw) }));
const groups: { name: string; title: string; raws: typeof raws }[] = [
  { name: 'ci', title: 'CI (primary): GitHub-hosted `ubuntu-latest`, three replicate VMs', raws: raws.filter((r) => r.env.env === 'ci') },
  { name: 'laptop', title: 'Laptop (reduced set)', raws: raws.filter((r) => r.env.env === 'laptop') },
].filter((g) => g.raws.length > 0);

const QS = [0.5, 0.95, 0.99] as const;
const sizeLabel = (s: string): string => (s in SIZES ? SIZES[s as keyof typeof SIZES].label : s);
const f2 = (x: number) => (Number.isFinite(x) ? x.toFixed(2) : 'n/a');
const est = (e: Estimate | undefined) => (e ? `${f2(e.value)} (${f2(e.lo)}–${f2(e.hi)})` : 'n/a');
const sgn = (e: Estimate | undefined) => (e ? `${e.value >= 0 ? '+' : ''}${f2(e.value)} (${f2(e.lo)}–${f2(e.hi)})` : 'n/a');

type LatencyRun = { samples: Record<string, Record<string, number[]>> };
type BreakdownRun = { samples: Record<string, Record<string, number[]>>; stages: Record<string, Record<string, number>[]> };
type DecisionRun = { cases: Record<string, { samples: number[]; deadline: number; n: number; fill?: Record<string, number> }> };
type MemoryRun = { series: Record<string, { calls: number; rss: number; heapUsed: number; tierABytes: number; tierBEntries: number; evicted: number }[]> };

/** `[vm][launch][sample]` for one part/size/arm. */
// eslint-disable-next-line @typescript-eslint/no-unnecessary-type-parameters -- names the raw run shape at each call site
function nest<T>(rs: typeof raws, part: string, pick: (run: T) => number[] | undefined): Nested {
  return rs.map((r) => ((r.results[part] as T[] | undefined) ?? []).map((run) => pick(run) ?? []));
}
const hasData = (n: Nested) => n.some((vm) => vm.some((l) => l.length > 0));

const L: string[] = [
  '# Latency, memory and eviction loss',
  '',
  'Phase 7 item 5, pre-registered in `bench/perf/PREREGISTRATION-perf.md` (committed and pushed before the first run).',
  `Generated from ${files.map((f) => `\`bench/results/perf/${f}\``).join(', ') || 'no raw files'} by \`bench/perf/report.mts\`.`,
  '',
  `Percentiles: nearest rank on pooled samples. Intervals: 95% cluster bootstrap (B = ${BOOTSTRAP_B}, seed ${BOOTSTRAP_SEED}), resampling`,
  'VMs, then launches, then samples (the laptop has one VM). Gateway − direct deltas are paired at the launch level. All times in ms.',
  '',
  '## Environments',
  '',
  '| file | where | date | commit | CPU | cores | memory | OS | Node | power | launches |',
  '|---|---|---|---|---|---|---|---|---|---|---|',
  ...raws.map((r) => `| ${r.file} | ${r.env.runner} | ${r.env.date} | \`${r.env.commit.slice(0, 7)}\` | ${r.env.cpu} | ${r.env.cores} | ${r.env.memGb} GB | ${r.env.os} | ${r.env.node} | ${r.env.power} | ${r.env.launches} |`),
  '',
  'The CI runner is a **shared VM, not a quiet machine**: the per-VM and per-launch spreads below are part of the result.',
  '',
];

// ---- L ----------------------------------------------------------------------------------------------------
L.push('## L — round trip, direct vs gateway', '');
for (const g of groups) {
  const sizes = [...new Set(g.raws.flatMap((r) => ((r.results.latency as LatencyRun[] | undefined) ?? []).flatMap((x) => Object.keys(x.samples))))];
  if (sizes.length === 0) continue;
  L.push(`### ${g.title}`, '', '| size | gateway arm | calls (direct / gateway) | direct p50 | p95 | p99 | gateway p50 | p95 | p99 | Δ p50 | Δ p95 | Δ p99 |', '|---|---|---|---|---|---|---|---|---|---|---|---|');
  const variance: string[] = [];
  for (const s of sizes) {
    const label = s === 'real64k' ? 'real server: server-filesystem `read_text_file`, 64 KiB' : (sizeLabel(s));
    const direct = nest<LatencyRun>(g.raws, 'latency', (x) => x.samples[s]?.direct);
    const arms = [...new Set(g.raws.flatMap((r) => ((r.results.latency as LatencyRun[] | undefined) ?? []).flatMap((x) => Object.keys(x.samples[s] ?? {}))))].filter((a) => a !== 'direct');
    const d = bootstrapQuantiles(direct, QS);
    variance.push(`| ${label} | direct | ${fmtSpread(direct)} |`);
    for (const a of arms) {
      const gw = nest<LatencyRun>(g.raws, 'latency', (x) => x.samples[s]?.[a]);
      const q = bootstrapQuantiles(gw, QS);
      const dl = bootstrapDeltas(gw, direct, QS);
      L.push(`| ${label} | ${a.replace('gateway/', 'payloads: ')} | ${direct.flat(2).length} / ${gw.flat(2).length} | ${est(d[0])} | ${est(d[1])} | ${est(d[2])} | ${est(q[0])} | ${est(q[1])} | ${est(q[2])} | ${sgn(dl[0])} | ${sgn(dl[1])} | ${sgn(dl[2])} |`);
      variance.push(`| ${label} | ${a} | ${fmtSpread(gw)} |`);
    }
  }
  L.push('', `Run-to-run variance (${g.name}): p50 of each launch, and of each VM.`, '', '| size | arm | launch p50: min / median / max | CV of launch p50 | p50 per VM |', '|---|---|---|---|---|', ...variance, '');
}
function fmtSpread(n: Nested): string {
  const s = spread(n);
  return `${f2(s.launchP50.min)} / ${f2(s.launchP50.median)} / ${f2(s.launchP50.max)} | ${(s.launchP50.cv * 100).toFixed(1)}% | ${s.vmP50.map(f2).join(', ')}`;
}

// ---- B ----------------------------------------------------------------------------------------------------
const STAGES = ['down.parse', 'down.validate', 'resolve', 'decide', 'audit.decision', 'sent', 'up.send', 'up.parse', 'up.validate', 'ingest', 'audit.ingest', 'audit.request', 'down.respond', 'down.send', 'down.drain'];
L.push('## B — cost breakdown of one `tools/call`', '');
L.push('Stages are timestamped inside the gateway process by the internal timing hook (bench entry `bench/perf/timed-gateway.mts`, hook on).', '**Gateway overhead** = client round trip − `up.wait` (upstream pipe + fixture). `redact` and `store.write` are the parts of the three `audit.*` stages', 'spent redacting payloads and inserting into SQLite. **Unattributed** = overhead − the stages listed (pipe transfer to and from the client, scheduling).', '');
for (const g of groups) {
  const runs = (r: (typeof raws)[number]) => (r.results.breakdown as BreakdownRun[] | undefined) ?? [];
  const sizes = [...new Set(g.raws.flatMap((r) => runs(r).flatMap((x) => Object.keys(x.stages))))];
  if (sizes.length === 0) continue;
  L.push(`### ${g.title}`, '');
  for (const s of sizes) {
    const per = (k: string): Nested => nest<BreakdownRun>(g.raws, 'breakdown', (x) => x.stages[s]?.map((c) => c[k] ?? 0));
    const overhead: Nested = nest<BreakdownRun>(g.raws, 'breakdown', (x) => x.stages[s]?.map((c, i) => (x.samples[s]?.['entry-on']?.[i] ?? NaN) - (c['up.wait'] ?? 0)));
    const ov = bootstrapQuantiles(overhead, [0.5])[0];
    const means = new Map<string, number>();
    const meanOf = (n: Nested) => { const xs = n.flat(2); return xs.reduce((a, b) => a + b, 0) / xs.length; };
    const ovMean = meanOf(overhead);
    L.push(`**${sizeLabel(s)}** — round trip p50 ${est(bootstrapQuantiles(nest<BreakdownRun>(g.raws, 'breakdown', (x) => x.samples[s]?.['entry-on']), [0.5])[0])}; \`up.wait\` p50 ${est(bootstrapQuantiles(per('up.wait'), [0.5])[0])}; gateway overhead p50 ${est(ov)}, mean ${f2(ovMean)}.`, '');
    L.push('| stage | p50 | mean | share of mean overhead |', '|---|---|---|---|');
    let covered = 0;
    for (const k of STAGES) {
      const n = per(k);
      const m = meanOf(n);
      means.set(k, m);
      covered += m;
      L.push(`| \`${k}\` | ${est(bootstrapQuantiles(n, [0.5])[0])} | ${f2(m)} | ${((m / ovMean) * 100).toFixed(1)}% |`);
    }
    for (const k of ['redact', 'store.write']) {
      const m = meanOf(per(k));
      L.push(`| of which \`${k}\` | ${est(bootstrapQuantiles(per(k), [0.5])[0])} | ${f2(m)} | ${((m / ovMean) * 100).toFixed(1)}% |`);
    }
    const sdk = ['down.parse', 'down.validate', 'up.parse', 'up.validate'].reduce((a, k) => a + (means.get(k) ?? 0), 0);
    L.push(`| SDK parse + validation (4 stages) | | ${f2(sdk)} | ${((sdk / ovMean) * 100).toFixed(1)}% |`);
    L.push(`| unattributed | | ${f2(ovMean - covered)} | ${(((ovMean - covered) / ovMean) * 100).toFixed(1)}% |`, '');
  }
  L.push('**Hook overhead** (Δ p50, paired by launch):', '', '| size | bench entry, hook on − hook off | bench entry, hook off − CLI |', '|---|---|---|');
  for (const s of sizes) {
    const arm = (a: string) => nest<BreakdownRun>(g.raws, 'breakdown', (x) => x.samples[s]?.[a]);
    L.push(`| ${sizeLabel(s)} | ${sgn(bootstrapDeltas(arm('entry-on'), arm('entry-off'), [0.5])[0])} | ${sgn(bootstrapDeltas(arm('entry-off'), arm('cli'), [0.5])[0])} |`);
  }
  L.push('');
}

// ---- D ----------------------------------------------------------------------------------------------------
const CASES: Record<string, string> = {
  small: 'small arguments', body128k: '128 KB body', slash128k: '128 KB slash-heavy body (R6b-10)', body1m: '1 MiB body (policy size check: fast deny)',
  'prose64-empty': '64-character prose body, empty index', 'prose64-full': '64-character prose body, Tier A full (32 MiB)',
  'prose8k-full': '8 KiB prose body, Tier A full (32 MiB) — amendment 2',
};
for (const g of groups) {
  const runs = (r: (typeof raws)[number]) => (r.results.decision as DecisionRun[] | undefined) ?? [];
  if (!g.raws.some((r) => runs(r).length)) continue;
  L.push(`## D — decision level, in process (${g.name})`, '', 'The `bench:policy` configuration. Whole decision (attribution + policy + invariant).', '', '| case | calls | p50 | p95 | p99 | denied by the 50 ms policy deadline |', '|---|---|---|---|---|---|');
  for (const [id, label] of Object.entries(CASES)) {
    const n = nest<DecisionRun>(g.raws, 'decision', (x) => x.cases[id]?.samples);
    if (!hasData(n)) continue;
    const q = bootstrapQuantiles(n, QS);
    const all = g.raws.flatMap((r) => runs(r).map((x) => x.cases[id]));
    const k = all.reduce((a, c) => a + (c?.deadline ?? 0), 0);
    const tot = all.reduce((a, c) => a + (c?.n ?? 0), 0);
    L.push(`| ${label} | ${tot} | ${est(q[0])} | ${est(q[1])} | ${est(q[2])} | ${rate(k, tot)} |`);
  }
  const fill = g.raws.flatMap((r) => runs(r).map((x) => x.cases['prose64-full']?.fill)).find(Boolean);
  if (fill) L.push('', `Full-index case: ${fill.outputs} outputs of 8 KiB ingested, Tier A ${((fill.tierABytes ?? 0) / 2 ** 20).toFixed(1)} MiB in ${fill.tierAOutputs} outputs, ${fill.evicted} evicted.`);
  L.push('');
}

// ---- M2 ---------------------------------------------------------------------------------------------------
for (const g of groups) {
  const runs = (r: (typeof raws)[number]) => (r.results.memory as MemoryRun[] | undefined) ?? [];
  const all = g.raws.flatMap(runs);
  if (all.length === 0) continue;
  L.push(`## M2 — long session (${g.name})`, '', '4,000 calls echoing 8 KiB of identifier-free prose through a real gateway process. Medians across launches (and VMs); MiB.', '');
  L.push('| budget | calls | RSS | heapUsed | Tier A | Tier B entries | evicted |', '|---|---|---|---|---|---|---|');
  const mib = (b: number) => (b / 2 ** 20).toFixed(1);
  const checks: string[] = [];
  for (const b of Object.keys(all[0]?.series ?? {}).sort((x, y) => Number(y) - Number(x))) {
    const series = all.map((r) => r.series[b] ?? []);
    for (const at of [100, 1000, 2000, 3000, 4000]) {
      const pts = series.map((s) => s.find((p) => p.calls === at)).filter((p): p is NonNullable<typeof p> => !!p);
      if (!pts.length) continue;
      L.push(`| ${b} | ${at} | ${mib(median(pts.map((p) => p.rss)))} | ${mib(median(pts.map((p) => p.heapUsed)))} | ${mib(median(pts.map((p) => p.tierABytes)))} | ${median(pts.map((p) => p.tierBEntries))} | ${median(pts.map((p) => p.evicted))} |`);
    }
    const maxA = Math.max(...series.flat().map((p) => p.tierABytes));
    const growth = series.map((s) => {
      const reach = s.find((p) => p.evicted > 0);
      const end = s[s.length - 1];
      return reach && end ? (end.rss - reach.rss) / reach.rss : NaN;
    });
    checks.push(`- budget ${b} MiB: max Tier A over every sample ${mib(maxA)} MiB (${maxA <= Number(b) * 2 ** 20 ? 'within' : '**over**'} the budget); RSS growth from the first eviction to the end: median ${(median(growth) * 100).toFixed(1)}%, max ${(Math.max(...growth) * 100).toFixed(1)}%.`);
  }
  L.push('', ...checks, '');
}

// ---- E + M1 -----------------------------------------------------------------------------------------------
const evRaw = raws.filter((r) => Array.isArray(r.results.eviction));
const E: string[] = ['# Eviction loss', '', 'Phase 7 item 5, pre-registered in `bench/perf/PREREGISTRATION-perf.md`. Deterministic decision-level replay (as in item 3) of the item-3 suite and', 'the policy family, unchanged (F0) and with filler at each `taint.max_index_mb` budget. Filler steps are excluded from every oracle.', ''];
if (evRaw.length) {
  const rows = evRaw.flatMap((r) => r.results.eviction as TraceRun[]);
  E.push(`Source (shards, merged): ${evRaw.map((r) => `\`bench/results/perf/${r.file}\` (${String(r.results.shard)}, ${r.env.runner})`).join(', ')}.`, '');
  E.push('| arm | what |', '|---|---|', ...ARMS.map((a) => `| ${a.id} | ${a.name} |`), '', `Budgets (MiB): ${BUDGETS.join(', ')}.`, '');
  E.push('Columns: attack success, partial leaks, utility under attack — claimed attacks; false blocks — benign traces; Wilson 95%. **Fail-closed denies** — decisions on', 'the trace\'s own steps denied with a `fail-closed` reason. **Verdict / evidence changes** — decisions on the trace\'s own steps that differ from F0.', '');
  const load = (f: string) => (JSON.parse(fs.readFileSync(path.join(here, '..', 'attack', f), 'utf8')) as unknown[]).map(loadScenario);
  const sets = [
    { id: 'suite', title: 'Item-3 suite (83 traces, unchanged)', scenarios: load('scenarios.json') },
    { id: 'policy', title: 'Policy family (8 traces, unchanged)', scenarios: load('scenarios-policy.json') },
  ];
  E.push(...evictionReport(rows, sets));
  E.push('## M1 — index size at the end of each trace (F0, defaults)', '', ...memoryPerTrace(rows), '');
}

fs.writeFileSync(path.join(RESULTS, 'perf.md'), `${L.join('\n')}\n`);
fs.writeFileSync(path.join(RESULTS, 'eviction.md'), `${E.join('\n')}\n`);
process.stdout.write(`wrote bench/results/perf.md and bench/results/eviction.md from ${files.length} raw file(s)\n`);
