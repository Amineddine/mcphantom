import type { CelInput } from '@bufbuild/cel';
import type { Config } from '../config/schema.js';
import type { Label } from '../taint/labels.js';
import { leaves } from '../taint/text.js';
import { compile, evaluate, CelError, type CompiledExpr } from './cel.js';
import { buildFunctions, type PolicyContext } from './functions.js';

export type PolicyEffect = 'deny' | 'ask' | 'allow';

export interface CompiledRule {
  effect: PolicyEffect;
  expr: CompiledExpr;
  /** `<serverId>.<tool>` or `declassify:<id>` — for the trace and lint messages. */
  origin: string;
}

export interface CompiledDeclassify {
  id: string;
  tool: string;
  when: CompiledExpr;
  reason: string;
}

export interface PolicyMatch {
  effect: PolicyEffect;
  origin: string;
}

export interface PolicyOutcome {
  /** Strongest matching rule effect, or undefined if no rule matched. */
  effect: PolicyEffect | undefined;
  matches: PolicyMatch[];
  /** A declassify entry whose condition held (lifts the trifecta invariant). */
  declassified: { id: string; reason: string } | undefined;
  /** Evaluation errors (absent arg, timeout, bad expression) — each forces a deny. */
  errors: { origin: string; message: string }[];
}

export interface EvalInputs {
  serverId: string;
  toolName: string;
  args: unknown;
  context: Label;
  provenanceOf: (value: string) => Set<'trusted' | 'untrusted'>;
}

/** Argument-size caps that bound policy evaluation cost (owner note #2): total string bytes and the
 *  number of leaves (so thousands of tiny fields cannot make CEL's map handling slow). Over either, the
 *  call is denied with a clear reason before any rule runs. */
const MAX_ARG_BYTES = 256 * 1024;
const MAX_ARG_LEAVES = 4096;
const EVAL_BUDGET_MS = 50;

const PRECEDENCE: Record<PolicyEffect, number> = { allow: 0, ask: 1, deny: 2 };

/**
 * Compiles and evaluates per-tool policy rules and declassify conditions. Separate from the taint
 * engine: it is given the context label and a provenance callback, and returns a verdict the gateway
 * combines with the trifecta invariant.
 *
 * Fail-closed throughout: a rule that references an argument absent from the call, an expression error,
 * or a blown time/size budget all produce a deny (recorded with the reason), never a silent non-match.
 */
export class PolicyEngine {
  private readonly rules = new Map<string, CompiledRule[]>();
  private readonly declassify: CompiledDeclassify[] = [];

  constructor(private readonly config: Config) {
    for (const [serverId, server] of Object.entries(config.servers)) {
      for (const [toolName, cls] of Object.entries(server.tools)) {
        if (!cls.rules) continue;
        const compiled: CompiledRule[] = [];
        for (const rule of cls.rules) {
          const effect: PolicyEffect = rule.deny !== undefined ? 'deny' : rule.ask !== undefined ? 'ask' : 'allow';
          const source = rule.deny ?? rule.ask ?? rule.allow ?? '';
          compiled.push({ effect, expr: compile(source), origin: `${serverId}.${toolName}` });
        }
        this.rules.set(`${serverId}__${toolName}`, compiled);
      }
    }
    for (const d of config.declassify) this.declassify.push({ id: d.id, tool: d.tool, when: compile(d.when), reason: d.reason });
  }

  /** Argument names each rule/declassify references, keyed by `<serverId>__<tool>` (for lint). */
  argRefsByTool(): Map<string, Set<string>> {
    const out = new Map<string, Set<string>>();
    for (const [key, rules] of this.rules) {
      const set = new Set<string>();
      for (const r of rules) for (const a of r.expr.allArgRefs) set.add(a);
      out.set(key, set);
    }
    return out;
  }

  get declassifyRules(): readonly CompiledDeclassify[] {
    return this.declassify;
  }

  evaluate(inputs: EvalInputs): PolicyOutcome {
    const exposed = `${inputs.serverId}__${inputs.toolName}`;
    const rules = this.rules.get(exposed) ?? [];
    const declass = this.declassify.filter((d) => d.tool === exposed || d.tool === `${inputs.serverId}.${inputs.toolName}`);
    const outcome: PolicyOutcome = { effect: undefined, matches: [], declassified: undefined, errors: [] };
    if (rules.length === 0 && declass.length === 0) return outcome;

    const argObj = (inputs.args ?? {}) as Record<string, unknown>;
    const present = new Set(topLevelKeys(argObj));
    const allLeaves = leaves(argObj);
    const bytes = allLeaves.reduce((n, l) => n + l.value.length, 0);
    if (allLeaves.length > MAX_ARG_LEAVES) {
      outcome.errors.push({ origin: exposed, message: `arguments have too many fields to evaluate policy (${allLeaves.length} > ${MAX_ARG_LEAVES})` });
      outcome.effect = 'deny';
      return outcome;
    }
    const ctx: PolicyContext = { provenanceOf: inputs.provenanceOf, deadline: Date.now() + EVAL_BUDGET_MS };
    const funcs = buildFunctions(ctx);
    const bindings: Record<string, CelInput> = { arg: toCel(argObj), context: { integrity: inputs.context.integrity, confidentiality: inputs.context.confidentiality } };

    if (bytes > MAX_ARG_BYTES) {
      outcome.errors.push({ origin: exposed, message: `arguments too large to evaluate policy (${bytes} > ${MAX_ARG_BYTES} bytes)` });
      outcome.effect = 'deny';
      return outcome;
    }

    for (const rule of rules) {
      const missing = [...rule.expr.argRefs].filter((a) => !present.has(a));
      if (missing.length > 0) {
        // A rule that names an argument the call did not supply fails closed (note #1).
        outcome.errors.push({ origin: rule.origin, message: `rule references argument(s) not in the call: ${missing.join(', ')}` });
        outcome.effect = 'deny';
        continue;
      }
      try {
        if (evaluate(rule.expr, bindings, funcs)) {
          outcome.matches.push({ effect: rule.effect, origin: rule.origin });
          if (outcome.effect === undefined || PRECEDENCE[rule.effect] > PRECEDENCE[outcome.effect]) outcome.effect = rule.effect;
        }
      } catch (err) {
        outcome.errors.push({ origin: rule.origin, message: err instanceof CelError ? err.message : String(err) });
        outcome.effect = 'deny';
      }
    }

    for (const d of declass) {
      const missing = [...d.when.argRefs].filter((a) => !present.has(a));
      if (missing.length > 0) continue; // a declassify that cannot apply simply does not lift the invariant
      try {
        if (evaluate(d.when, bindings, funcs)) outcome.declassified = { id: d.id, reason: d.reason };
      } catch {
        // A failing declassify never lifts the invariant; it just does not apply.
      }
    }
    return outcome;
  }
}

function topLevelKeys(args: Record<string, unknown>): string[] {
  return Object.keys(args);
}


/** Converts arguments to CEL inputs: plain JSON maps/lists/scalars pass through as-is. */
function toCel(v: unknown): CelInput {
  return v as CelInput;
}
