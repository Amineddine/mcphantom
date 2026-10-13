import { celFunc, CelScalar, listType } from '@bufbuild/cel';
import { findSecrets } from '../secrets/detectors.js';
import { hasOutsideTarget } from '../taint/egress.js';
import { globMatchAny } from './glob.js';
import type { CelFuncDef } from './cel.js';

/**
 * Context the custom predicates close over for one evaluation. Provenance lookups come from a callback
 * so the policy layer does not import the taint internals directly.
 */
export interface PolicyContext {
  /** Returns the integrity levels attributed to a string value by the provenance index. */
  provenanceOf(value: string): Set<'trusted' | 'untrusted'>;
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
 *  - `containsSecret(s)`    — the string contains a detectable credential.
 *  - `from(s, level)`       — the string is attributed to an output of the given integrity level.
 *
 * `from(..., "untrusted")` with no match returns false — a *precision-mode* predicate: absence of a
 * provenance match is not proof of absence of flow (encoding/paraphrase). The linter warns on any rule
 * that relies on it, and Layer 1 still applies. This is the documented, bypassable layer.
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
      return findSecrets(value).length > 0;
    }),
    celFunc('from', [CelScalar.STRING, CelScalar.STRING], CelScalar.BOOL, (value: string, level: string) => {
      checkDeadline(ctx);
      if (level !== 'trusted' && level !== 'untrusted') throw new Error(`from(): unknown integrity level "${level}"`);
      return ctx.provenanceOf(value).has(level);
    }),
  ];
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
