import { parse, run, type CelInput } from '@bufbuild/cel';

/**
 * Thin wrapper over @bufbuild/cel. A `CompiledExpr` is parsed once (so we can also walk it for the
 * `arg.*` references a rule depends on) and evaluated many times. The evaluator result is coerced to a
 * strict boolean: a non-boolean result is a policy authoring error, surfaced by the caller.
 *
 * CEL has no loops or recursion, so evaluation time is bounded by the AST size and by our own custom
 * functions. We additionally cap AST node count at compile and argument size at eval (see engine.ts),
 * and custom predicates check a deadline — that is the per-evaluation cost budget.
 */
export interface CompiledExpr {
  source: string;
  /** `arg.<field>` references the expression *requires*: referenced and not guarded by `has()`.
   *  A call missing one of these fails closed. */
  argRefs: Set<string>;
  /** Every `arg.<field>` referenced, guarded or not — what the linter checks against the schema. */
  allArgRefs: Set<string>;
  nodeCount: number;
}

export class CelError extends Error {}

const MAX_NODES = 2000;

interface Refs {
  all: Set<string>;
  guarded: Set<string>;
}

export function compile(source: string): CompiledExpr {
  let ast: ReturnType<typeof parse>;
  try {
    ast = parse(source);
  } catch (err) {
    throw new CelError(`parse error: ${err instanceof Error ? err.message : String(err)}`);
  }
  const refs: Refs = { all: new Set(), guarded: new Set() };
  const nodeCount = walk((ast as { expr?: unknown }).expr, refs);
  if (nodeCount > MAX_NODES) throw new CelError(`expression too large (${nodeCount} nodes > ${MAX_NODES})`);
  const argRefs = new Set([...refs.all].filter((a) => !refs.guarded.has(a)));
  return { source, argRefs, allArgRefs: refs.all, nodeCount };
}

export type CelFuncDef = ReturnType<typeof import('@bufbuild/cel').celFunc>;

export function evaluate(expr: CompiledExpr, bindings: Record<string, CelInput>, funcs: CelFuncDef[]): boolean {
  let result: unknown;
  try {
    result = run(expr.source, bindings, { funcs });
  } catch (err) {
    throw new CelError(err instanceof Error ? err.message : String(err));
  }
  if (typeof result !== 'boolean') throw new CelError(`expression must evaluate to a boolean, got ${typeof result}`);
  return result;
}

/**
 * Walks the CEL AST, counting nodes and collecting the first-level field of each `arg.<field>`. A
 * test-only select — the form `has(arg.x)` parses to — marks the field as guarded: the author has
 * explicitly handled its absence, so it is not a required argument.
 */
function walk(node: unknown, refs: Refs, depth = 0): number {
  if (!node || typeof node !== 'object' || depth > 500) return 0;
  const expr = node as { exprKind?: { case?: string; value?: unknown } };
  const kind = expr.exprKind;
  if (!kind || typeof kind.case !== 'string') return 1;
  let count = 1;
  const v = kind.value as Record<string, unknown> | undefined;
  switch (kind.case) {
    case 'selectExpr': {
      const sel = v as { operand?: unknown; field?: unknown; testOnly?: unknown } | undefined;
      const operand = sel?.operand as { exprKind?: { case?: string; value?: { name?: unknown } } } | undefined;
      if (operand?.exprKind?.case === 'identExpr' && operand.exprKind.value?.name === 'arg' && typeof sel?.field === 'string') {
        refs.all.add(sel.field);
        if (sel.testOnly === true) refs.guarded.add(sel.field);
      }
      count += walk(sel?.operand, refs, depth + 1);
      break;
    }
    case 'callExpr': {
      const call = v as { target?: unknown; args?: unknown[] } | undefined;
      count += walk(call?.target, refs, depth + 1);
      for (const a of call?.args ?? []) count += walk(a, refs, depth + 1);
      break;
    }
    case 'listExpr': {
      for (const e of (v as { elements?: unknown[] } | undefined)?.elements ?? []) count += walk(e, refs, depth + 1);
      break;
    }
    case 'structExpr': {
      for (const e of (v as { entries?: { value?: unknown }[] } | undefined)?.entries ?? []) count += walk(e.value, refs, depth + 1);
      break;
    }
    case 'comprehensionExpr': {
      for (const key of ['iterRange', 'accuInit', 'loopCondition', 'loopStep', 'result']) count += walk(v?.[key], refs, depth + 1);
      break;
    }
    default:
      break;
  }
  return count;
}
