import { celFunc, CelScalar, listType } from '@bufbuild/cel';
import { secretRuleIn } from '../secrets/in-value.js';
import { hasOutsideTarget } from '../taint/egress.js';
import { globMatchAny } from './glob.js';
import type { CelFuncDef } from './cel.js';

/**
 * Context the custom predicates close over for one evaluation. Provenance lookups come from a callback
 * so the policy layer does not import the taint internals directly.
 */
export interface PolicyContext {
  /** Returns the integrity levels attributed to a string value by the provenance index. With
   *  `deterministic`, only exact / normalized / decoded evidence counts (no fuzzy similarity). */
  provenanceOf(value: string, deterministic: boolean): Set<'trusted' | 'untrusted'>;
  /** Why a missing match for `level` proves nothing for this value (attribution lost track of outputs
   *  of that level, or could not check the value in full), with the way out; undefined if it does. */
  unsure?(value: string, level: 'trusted' | 'untrusted'): string | undefined;
  /** True while an `allow` rule or a declassify condition is evaluated: evidence that can ground an
   *  allow must be deterministic (owner decision: fuzzy and cumulative evidence never grounds one). */
  allowSide?: boolean;
  /** Deadline for the whole evaluation, on the `now` clock; predicates throw if it has passed. */
  deadline: number;
  now?: () => number;
}

function checkDeadline(ctx: PolicyContext): void {
  if ((ctx.now ? ctx.now() : performance.now()) > ctx.deadline) throw new Error('policy evaluation exceeded its time budget');
}

/**
 * The custom CEL predicates available to policy rules:
 *  - `glob(path, patterns)` — path matches any glob pattern.
 *  - `within(path, root)`   — path stays inside root (no remote URL, no `..` escape, not absolute-out).
 *  - `containsSecret(s)`    — the string contains a detectable credential, in clear or under an
 *                             encoding (base64, hex, URL, entities, escapes, spacing, rot13,
 *                             reversal) or a look-alike disguise. Deny-side only, so decoding can
 *                             only tighten a decision.
 *  - `from(s, level)`       — the string is attributed to an output of the given integrity level.
 *
 * `from(..., "untrusted")` with no match returns false — a *precision-mode* predicate: absence of a
 * provenance match is not proof of absence of flow (encoding/paraphrase). The linter warns on any rule
 * that relies on it, and Layer 1 still applies. This is the documented, bypassable layer. In a deny or
 * ask rule, a missing match where attribution lost track of outputs of that level (eviction, partial
 * decoding) or could not check the value in full is an error instead, so the rule fails closed.
 */
export function buildFunctions(ctx: PolicyContext): CelFuncDef[] {
  return [
    celFunc('glob', [CelScalar.STRING, listType(CelScalar.STRING)], CelScalar.BOOL, (value: string, patterns: unknown) => {
      checkDeadline(ctx);
      return globMatchAny(value, toStringArray(patterns));
    }),
    celFunc('within', [CelScalar.STRING, CelScalar.STRING], CelScalar.BOOL, (value: string, root: string) => {
      checkDeadline(ctx);
      return !hasOutsideTarget({ p: value }, root, ['p']);
    }),
    celFunc('containsSecret', [CelScalar.STRING], CelScalar.BOOL, (value: string) => {
      checkDeadline(ctx);
      return containsSecret(value, ctx);
    }),
    celFunc('from', [CelScalar.STRING, CelScalar.STRING], CelScalar.BOOL, (value: string, level: string) => {
      checkDeadline(ctx);
      if (level !== 'trusted' && level !== 'untrusted') throw new Error(`from(): unknown integrity level "${level}"`);
      if (ctx.provenanceOf(value, ctx.allowSide === true).has(level)) return true;
      // Deny side: where attribution could have missed the match, fail closed (R7p-3, Phase 7). An error,
      // not `true`, so a negated `!from(...)` fails closed too; CEL still lets `false && error` be false.
      const why = ctx.allowSide === true ? undefined : ctx.unsure?.(value, level);
      if (why) throw new Error(`from(): fail-closed: ${why}`);
      return false;
    }),
  ];
}

function containsSecret(value: string, ctx: PolicyContext): boolean {
  return secretRuleIn(value, () => {
    checkDeadline(ctx);
  }) !== undefined;
}

/** Names of the custom functions, for the linter to recognise. */
export const CUSTOM_FUNCTIONS = ['glob', 'within', 'containsSecret', 'from'] as const;

/** `from(...)` and `within(...)` with an untrusted argument are the bypassable precision-mode checks. */
export const PRECISION_FUNCTIONS = ['from'] as const;

/** CEL hands list arguments as a CelList (iterable), not a plain Array. */
function toStringArray(v: unknown): string[] {
  const arr = Array.isArray(v) ? v : isIterable(v) ? [...v] : [];
  return arr.filter((x): x is string => typeof x === 'string');
}

function isIterable(v: unknown): v is Iterable<unknown> {
  return v != null && typeof (v as { [Symbol.iterator]?: unknown })[Symbol.iterator] === 'function';
}
