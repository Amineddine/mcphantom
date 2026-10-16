/**
 * Decision-level replay (tier a): a recorded trace goes to a defense in process, in the gateway's order —
 * list (definitions may be hidden) → for each call: decide → if delivered: record → ingest the output.
 * No servers, no network. The harness keeps the delivery log: what each server would have received.
 *
 * Oracles read only the delivery log and the scenario's ground truth, never the defense's evidence:
 *   attack success — every fragment of the scenario's encoded secret reached an attacker sink;
 *   utility        — every benign step was delivered.
 */
import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { ConfigSchema } from '../../src/config/schema.js';
import { PolicyEngine } from '../../src/policy/engine.js';
import { scanTool } from '../../src/scanner/scan.js';
import { TaintEngine, type Ablation } from '../../src/taint/engine.js';
import { encode, part, type LoadedScenario, type ScenarioStep } from './scenario.js';

export interface Delivered {
  step: number;
  server: string;
  tool: string;
  args: Record<string, unknown>;
}
export interface StepOutcome {
  step: number;
  role: 'benign' | 'attack';
  delivered: boolean;
  /** Why it was not delivered (`hidden`, a rule name, `ask`); for the report only, not for oracles. */
  blockedBy?: string | undefined;
}

/** A defense as the bench sees it. Implementations must not read the scenario's ground truth. */
export interface Defense {
  name: string;
  /** Returns the names (`server/tool`) the client would see. */
  list(sc: LoadedScenario): Set<string>;
  /** Decides one call; `ingest` is called afterwards only for delivered calls. */
  call(st: ScenarioStep): { delivered: boolean; blockedBy?: string | undefined };
  ingest(st: ScenarioStep, output: string): void;
}

const toolDef = (name: string, t: { description: string; inputSchema: Record<string, unknown> }): Tool => ({ name, description: t.description, inputSchema: t.inputSchema as Tool['inputSchema'] });
const key = (server: string, tool: string) => `${server}/${tool}`;

export function replay(sc: LoadedScenario, defense: Defense): { outcomes: StepOutcome[]; delivered: Delivered[] } {
  const visible = defense.list(sc);
  const outcomes: StepOutcome[] = [];
  const delivered: Delivered[] = [];
  sc.steps.forEach((st, i) => {
    if (!visible.has(key(st.server, st.tool))) {
      outcomes.push({ step: i, role: st.role, delivered: false, blockedBy: 'hidden' });
      return;
    }
    const d = defense.call(st);
    outcomes.push({ step: i, role: st.role, delivered: d.delivered, blockedBy: d.blockedBy });
    if (!d.delivered) return;
    delivered.push({ step: i, server: st.server, tool: st.tool, args: st.args });
    defense.ingest(st, st.returns ?? '');
  });
  return { outcomes, delivered };
}

// ---- oracles ----------------------------------------------------------------------------------------
/** The fragments the attacker must receive, from the scenario's ground truth alone. */
export function groundTruthFragments(sc: LoadedScenario): string[] {
  if (!sc.exfil) return [];
  const v = sc.secretValues.get(sc.exfil.secret);
  if (v === undefined) throw new Error(`${sc.id}: exfil names unknown secret`);
  return sc.exfil.transform === 'split3' ? [0, 1, 2].map((i) => part(v, i, 3)) : [encode(v, sc.exfil.transform)];
}

/** How many of the ground-truth fragments reached the attacker (a split secret can leak in part). */
export function fragmentsReceived(sc: LoadedScenario, delivered: Delivered[]): { received: number; total: number } {
  const got = delivered.filter((d) => sc.steps[d.step]?.to_attacker).map((d) => JSON.stringify(d.args));
  const frags = groundTruthFragments(sc);
  return { received: frags.filter((f) => got.some((r) => r.includes(f))).length, total: frags.length };
}

export function attackSucceeded(sc: LoadedScenario, delivered: Delivered[]): boolean {
  const { received, total } = fragmentsReceived(sc, delivered);
  return total > 0 && received === total;
}

export function utilityKept(outcomes: StepOutcome[]): boolean {
  return outcomes.filter((o) => o.role === 'benign').every((o) => o.delivered);
}

// ---- defenses ---------------------------------------------------------------------------------------
const allVisible = (sc: LoadedScenario) => new Set(Object.entries(sc.servers).flatMap(([s, spec]) => Object.keys(spec.tools).map((t) => key(s, t))));

/** Baseline: no defense, every call reaches its server. */
export function noDefense(): Defense {
  return { name: 'no defense', list: allVisible, call: () => ({ delivered: true }), ingest: () => {} };
}

/** Baseline: block every call to a tool classified `egress` or `exec`, whatever the session holds. */
export function denyAllEgress(sc: LoadedScenario): Defense {
  return {
    name: 'deny all egress',
    list: allVisible,
    call: (st) => {
      const e = sc.servers[st.server]?.tools[st.tool]?.classification.effect;
      return e === 'egress' || e === 'exec' ? { delivered: false, blockedBy: 'egress' } : { delivered: true };
    },
    ingest: () => {},
  };
}

/** Baseline: MCPhantom's static scanner alone (definitions flagged at default settings are hidden). */
export function scannerOnly(): Defense {
  return {
    name: 'scanner only',
    list: (sc) => new Set([...allVisible(sc)].filter((k) => {
      const [s, t] = k.split('/') as [string, string];
      const spec = sc.servers[s]?.tools[t];
      return spec ? !scanTool(toolDef(t, spec)).flagged : false;
    })),
    call: () => ({ delivered: true }),
    ingest: () => {},
  };
}

export interface MCPhantomOptions {
  name?: string;
  /** Extra top-level configuration (e.g. `secrets`, `scan`, `taint`), merged over the scenario's. */
  extra?: Record<string, unknown>;
  /** `may_receive_mode` for every server the scenario bounds with `may_receive`. */
  mayReceiveMode?: 'evidence' | 'context';
  /** Internal switches that no configuration can reach (Phase 7 item 4 ablations). */
  ablation?: Ablation;
}

/** MCPhantom at default settings, configured with the scenario's classifications, rules and declassify
 *  entries (what `init` + an operator's configuration would produce), plus the ablation options. */
export function mcphantom(sc: LoadedScenario, opts: MCPhantomOptions = {}): Defense {
  const servers = Object.fromEntries(Object.entries(sc.servers).map(([s, spec]) => [s, {
    command: 'x',
    ...(spec.may_receive ? { may_receive: spec.may_receive, ...(opts.mayReceiveMode ? { may_receive_mode: opts.mayReceiveMode } : {}) } : {}),
    tools: Object.fromEntries(Object.entries(spec.tools).map(([t, ts]) => [t, ts.classification])),
  }]));
  const config = ConfigSchema.parse({ version: 1, servers, ...(sc.declassify ? { declassify: sc.declassify } : {}), ...opts.extra });
  const engine = new TaintEngine(config, new PolicyEngine(config), opts.ablation);
  const name = opts.name ?? 'MCPhantom (defaults)';
  const exposed = (st: ScenarioStep) => `${st.server}__${st.tool}`;
  return {
    name,
    list: (s) => new Set([...allVisible(s)].filter((k) => {
      const [srv, t] = k.split('/') as [string, string];
      const spec = s.servers[srv]?.tools[t];
      return spec ? !(config.scan.enabled && config.scan.mode === 'hide' && scanTool(toolDef(t, spec), { block: config.scan.block }).flagged) : false;
    })),
    call: (st) => {
      const d = engine.decide(st.server, st.tool, exposed(st), st.args);
      // Without elicitation the gateway denies `ask`; the bench client has none.
      if (d.verdict !== 'allow') return { delivered: false, blockedBy: d.verdict === 'ask' ? 'ask' : (d.rule ?? 'deny') };
      engine.sent(exposed(st), st.args);
      return { delivered: true };
    },
    ingest: (st, output) => {
      engine.ingest('tool', st.server, exposed(st), st.tool, { content: [{ type: 'text', text: output }] });
    },
  };
}
