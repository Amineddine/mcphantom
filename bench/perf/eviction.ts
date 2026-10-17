/**
 * E — eviction loss, and M1 — index memory per trace (Phase 7 item 5; pre-registered in
 * bench/perf/PREREGISTRATION-perf.md). Deterministic, in process, decision-level replay (as in item 3).
 *
 * The item-3 suite and the policy family are replayed unchanged (F0) and with filler inserted at the
 * insertion point (before the first attack step, or before the last step of a benign trace), at each
 * `taint.max_index_mb` budget:
 *   F1  128 × 8 KiB identifier-free prose from a trusted, public `docs/read_doc` tool;
 *   F2  the trace's own untrusted source called ⌈1.1 × budget / 64 KiB⌉ times, 64 KiB of prose each;
 *   F3  before the first step, 56 × 64 KiB of distinct random tokens from that source (Tier-B flood), then F2.
 * Filler steps are excluded from every oracle.
 */
import { attackSucceeded, fragmentsReceived, mcphantom, replay, utilityKept, type Defense } from '../attack/replay.js';
import type { LoadedScenario, ScenarioStep } from '../attack/scenario.js';
import { rate } from '../attack/stats.js';
import type { Decision, TaintEngine } from '../../src/taint/engine.js';
import { prose, tokens, tokensIn } from './filler.js';

export const BUDGETS = [32, 4, 1, 0.25, 0.0625] as const;
export type Arm = 'F0' | 'F1' | 'F2' | 'F3';
export const ARMS: { id: Arm; name: string }[] = [
  { id: 'F0', name: 'no filler (reference, defaults)' },
  { id: 'F1', name: 'benign filler: 128 × 8 KiB trusted public prose' },
  { id: 'F2', name: 'adversarial filler: the untrusted source, sized to the budget, right before the attack step' },
  { id: 'F3', name: 'identifier flood first (Tier B), then F2' },
];
const TIER_B_CAP = 200_000;
const KiB = 1024;
const MiB = 1024 * KiB;

const DOCS = { tools: { read_doc: { description: 'Read an internal document.', inputSchema: { type: 'object', properties: { name: { type: 'string' } }, required: ['name'] }, classification: { effect: 'read' as const, integrity: 'trusted' as const, confidentiality: 'public' as const } } } };

interface Built { sc: LoadedScenario; orig: (number | null)[]; fillerSteps: number }

/** The trace with filler inserted; `orig[i]` is the trace's own step index, or null for filler. */
export function withFiller(sc: LoadedScenario, arm: Arm, budgetMb: number, seed = 1): Built | null {
  const steps = sc.steps;
  const firstAttack = steps.findIndex((s) => s.role === 'attack');
  const insertAt = firstAttack >= 0 ? firstAttack : steps.length - 1;
  const own = steps.map((_, i) => i);
  if (arm === 'F0') return { sc, orig: own, fillerSteps: 0 };
  const filler = (server: string, tool: string, args: Record<string, unknown>, returns: string): ScenarioStep => ({ role: 'benign', server, tool, args, returns, to_attacker: false });
  let servers = sc.servers;
  let pre: ScenarioStep[] = [];
  let mid: ScenarioStep[];
  if (arm === 'F1') {
    servers = { ...sc.servers, docs: DOCS };
    mid = Array.from({ length: 128 }, (_, i) => filler('docs', 'read_doc', { name: `doc-${i}` }, prose(8 * KiB, seed * 1000 + i)));
  } else {
    const src = steps.find((s) => sc.servers[s.server]?.tools[s.tool]?.classification.integrity === 'untrusted');
    if (!src) return null;
    const n = Math.ceil((1.1 * budgetMb * MiB) / (64 * KiB));
    mid = Array.from({ length: n }, (_, i) => filler(src.server, src.tool, src.args, prose(64 * KiB, seed * 100_000 + i)));
    if (arm === 'F3') {
      const per = tokensIn(64 * KiB);
      pre = Array.from({ length: 56 }, (_, i) => filler(src.server, src.tool, src.args, tokens(per, seed * 1000 + i)));
    }
  }
  const out = [...pre, ...steps.slice(0, insertAt), ...mid, ...steps.slice(insertAt)];
  const orig = [...pre.map(() => null), ...own.slice(0, insertAt), ...mid.map(() => null), ...own.slice(insertAt)];
  return { sc: { ...sc, servers, steps: out }, orig, fillerSteps: pre.length + mid.length };
}

export interface TraceRun {
  set: string; arm: Arm; budget: number | null; id: string; kind: 'attack' | 'benign'; claimed: boolean;
  success: boolean | null; fragments: { received: number; total: number }; utility: boolean; blocked: string[];
  /** Per own step: verdict, rule, fail-closed, evidence keys. */
  decisions: ({ verdict: string; rule?: string; failClosed: boolean; evidence: string[] } | null)[];
  fillerSteps: number; fillerBlocked: number;
  index: { tierABytes: number; tierAOutputs: number; tierBEntries: number; evicted: number; sinks: number; sinkChars: number };
}

export function run(set: string, sc0: LoadedScenario, arm: Arm, budget: number | null): TraceRun | null {
  const built = withFiller(sc0, arm, budget ?? 0);
  if (!built) return null;
  const { sc, orig } = built;
  const stepIdx = new Map(sc.steps.map((s, i) => [s, i]));
  const outputStep = new Map<string, number | null>();
  const decisions: TraceRun['decisions'] = sc0.steps.map(() => null);
  let engine: TaintEngine | undefined;
  let ingests = 0;
  const def = mcphantom(sc, {
    name: arm, ...(budget !== null ? { extra: { taint: { max_index_mb: budget } } } : {}),
    onEngine: (e) => { engine = e; },
    observe: (st: ScenarioStep, d: Decision) => {
      const own = orig[stepIdx.get(st) ?? -1];
      if (own === null || own === undefined) return;
      decisions[own] = {
        verdict: d.verdict, ...(d.rule ? { rule: d.rule } : {}), failClosed: d.verdict === 'deny' && d.reason.includes('fail-closed'),
        evidence: [...new Set(d.evidence.map((e) => `${e.argPath}|${outputStep.get(e.output.id) ?? 'filler'}|${e.kind}|${e.matcher}`))].sort(),
      };
    },
  });
  const wrapped: Defense = {
    ...def,
    ingest: (st, output) => {
      ingests++;
      outputStep.set(`o${ingests}`, orig[stepIdx.get(st) ?? -1] ?? null);
      def.ingest(st, output);
    },
  };
  const { outcomes, delivered } = replay(sc, wrapped);
  const ownOutcomes = outcomes.filter((o) => orig[o.step] !== null);
  return {
    set, arm, budget, id: sc0.id, kind: sc0.kind, claimed: sc0.claimed,
    success: sc0.kind === 'attack' ? attackSucceeded(sc, delivered) : null,
    fragments: fragmentsReceived(sc, delivered),
    utility: utilityKept(ownOutcomes),
    blocked: ownOutcomes.filter((o) => !o.delivered).map((o) => `step ${orig[o.step] ?? '?'} (${o.role}): ${o.blockedBy ?? '?'}`),
    decisions, fillerSteps: built.fillerSteps, fillerBlocked: outcomes.filter((o) => orig[o.step] === null && !o.delivered).length,
    index: engine ? engine.indexStats : { tierABytes: 0, tierAOutputs: 0, tierBEntries: 0, evicted: 0, sinks: 0, sinkChars: 0 },
  };
}

const partialLeak = (r: TraceRun) => r.success === false && r.fragments.received > 0;
export function outcome(r: TraceRun): string {
  if (r.kind === 'benign') return r.utility ? 'delivered' : `false block (${r.blocked.join('; ')})`;
  if (r.success) return 'attack succeeded';
  if (partialLeak(r)) return `partial leak ${r.fragments.received}/${r.fragments.total} (${r.blocked.join('; ')})`;
  return `stopped (${r.blocked.filter((b) => b.includes('(attack)')).join('; ') || r.blocked.join('; ')})`;
}

/** `shard` = [i, n]: only traces whose position in their set is i mod n (amendment 3: E runs in shards). */
export function runAll(sets: { id: string; title: string; scenarios: LoadedScenario[] }[], opts: { smoke?: boolean; shard?: [number, number]; log?: (s: string) => void } = {}): TraceRun[] {
  const budgets = opts.smoke ? [0.0625] : [...BUDGETS];
  const rows: TraceRun[] = [];
  for (const set of sets) {
    const all = opts.smoke ? set.scenarios.slice(0, 4) : set.scenarios;
    const scs = opts.shard ? all.filter((_, i) => i % (opts.shard?.[1] ?? 1) === opts.shard?.[0]) : all;
    for (const sc of scs) {
      const ref = run(set.id, sc, 'F0', null);
      if (ref) rows.push(ref);
      for (const arm of ['F1', 'F2', 'F3'] as const) for (const b of budgets) {
        const r = run(set.id, sc, arm, b);
        if (r) rows.push(r);
      }
      opts.log?.(`${set.id}/${sc.id}\n`);
    }
  }
  return rows;
}

// ---- report ---------------------------------------------------------------------------------------------
const changed = (a: TraceRun['decisions'][number], b: TraceRun['decisions'][number]) => (a?.verdict ?? 'none') !== (b?.verdict ?? 'none');
const evChanged = (a: TraceRun['decisions'][number], b: TraceRun['decisions'][number]) => JSON.stringify(a?.evidence ?? []) !== JSON.stringify(b?.evidence ?? []);
const med = (xs: number[]) => { const s = [...xs].sort((a, b) => a - b); return s.length ? (s[Math.floor(s.length / 2)] ?? 0) : 0; };

export function report(rows: TraceRun[], sets: { id: string; title: string; scenarios: LoadedScenario[] }[]): string[] {
  const L: string[] = [];
  for (const set of sets) {
    const rs = rows.filter((r) => r.set === set.id);
    const ref = new Map(rs.filter((r) => r.arm === 'F0').map((r) => [r.id, r]));
    const ids = new Set(ref.keys());
    L.push(`### ${set.title}`, '');
    L.push('| arm | budget (MiB) | attack success | partial leaks | false blocks | utility under attack | fail-closed denies (decisions / traces) | verdict changes vs F0 (decisions) | evidence changes vs F0 (decisions) | Tier A evictions (median / trace) | Tier B at cap (traces) | filler calls not delivered |');
    L.push('|---|---|---|---|---|---|---|---|---|---|---|---|');
    const cells = new Map<string, TraceRun[]>();
    for (const r of rs) {
      const k = `${r.arm}|${r.budget ?? '—'}`;
      cells.set(k, [...(cells.get(k) ?? []), r]);
    }
    for (const [k, cs] of cells) {
      const [arm, budget] = k.split('|');
      const atk = cs.filter((r) => r.kind === 'attack' && r.claimed);
      const ben = cs.filter((r) => r.kind === 'benign');
      const fcDec = cs.reduce((a, r) => a + r.decisions.filter((d) => d?.failClosed).length, 0);
      const fcTr = cs.filter((r) => r.decisions.some((d) => d?.failClosed)).length;
      let vc = 0;
      let ec = 0;
      for (const r of cs) {
        const base = ref.get(r.id);
        if (!base) continue;
        r.decisions.forEach((d, i) => {
          if (changed(d, base.decisions[i] ?? null)) vc++;
          if (evChanged(d, base.decisions[i] ?? null)) ec++;
        });
      }
      L.push(`| ${arm} | ${budget} | ${rate(atk.filter((r) => r.success).length, atk.length)} | ${rate(atk.filter(partialLeak).length, atk.length)} | ${rate(ben.filter((r) => !r.utility).length, ben.length)} | ${rate(atk.filter((r) => r.utility).length, atk.length)} | ${fcDec} / ${fcTr} | ${vc} | ${ec} | ${med(cs.map((r) => r.index.evicted))} | ${cs.filter((r) => r.index.tierBEntries >= TIER_B_CAP).length} / ${cs.length} | ${cs.reduce((a, r) => a + r.fillerBlocked, 0)} |`);
    }
    L.push('', `Traces without an untrusted source have no F2/F3 row: ${[...ids].filter((id) => !rs.some((r) => r.id === id && r.arm === 'F2')).map((id) => `\`${id}\``).join(', ') || 'none'}.`, '');
    const outside = rs.filter((r) => r.kind === 'attack' && !r.claimed);
    if (outside.length) {
      L.push('Outside the claims (reported, not claimed):', '', '| arm | budget (MiB) | attack success | partial leaks |', '|---|---|---|---|');
      for (const [k, cs] of cells) {
        const o = cs.filter((r) => r.kind === 'attack' && !r.claimed);
        const [arm, budget] = k.split('|');
        L.push(`| ${arm} | ${budget} | ${rate(o.filter((r) => r.success).length, o.length)} | ${rate(o.filter(partialLeak).length, o.length)} |`);
      }
      L.push('');
    }
    L.push(`**Every trace whose outcome differs from F0** (grouped; budgets in MiB):`, '');
    const diffs = new Map<string, number[]>();
    for (const r of rs.filter((x) => x.arm !== 'F0')) {
      const base = ref.get(r.id);
      if (!base || outcome(r) === outcome(base)) continue;
      const k = `${r.id}|${r.arm}|${outcome(base)} → ${outcome(r)}`;
      diffs.set(k, [...(diffs.get(k) ?? []), r.budget ?? 0]);
    }
    if (diffs.size === 0) L.push('- none.');
    for (const [k, budgets] of [...diffs].sort()) {
      const [id, arm, what] = k.split('|');
      L.push(`- \`${id}\` ${arm} at ${budgets.join(', ')}: ${what}`);
    }
    L.push('');
  }
  return L;
}

/** M1: index size at the end of each trace replayed at defaults. */
export function memoryPerTrace(rows: TraceRun[]): string[] {
  const ref = rows.filter((r) => r.arm === 'F0');
  const L = ['| set | traces | Tier A bytes (median / max) | Tier A outputs (max) | Tier B entries (median / max) | sink characters (max) |', '|---|---|---|---|---|---|'];
  for (const set of [...new Set(ref.map((r) => r.set))]) {
    const rs = ref.filter((r) => r.set === set);
    const a = rs.map((r) => r.index.tierABytes);
    const b = rs.map((r) => r.index.tierBEntries);
    L.push(`| ${set} | ${rs.length} | ${med(a)} / ${Math.max(...a)} | ${Math.max(...rs.map((r) => r.index.tierAOutputs))} | ${med(b)} / ${Math.max(...b)} | ${Math.max(...rs.map((r) => r.index.sinkChars))} |`);
  }
  return L;
}
