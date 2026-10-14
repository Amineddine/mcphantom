/**
 * Does a value carry a known-format credential, in clear text, disguised (confusables, spacing) or
 * encoded (base64, hex, URL, ...)? Shared by the policy predicate `containsSecret()` and the per-server
 * `may_receive` bound. Entropy-only possible secrets are not counted: they are not known to be secrets.
 */
import { decodeVariants, type DecodeLimits } from '../text/decode.js';
import { fold } from '../text/normalize.js';
import { findSecrets } from './detectors.js';

const SECRET_DECODE_LIMITS: DecodeLimits = { maxDepth: 3, maxVariants: 32, maxChars: 256 * 1024, wholeOn: 'tokens' };
/** Characters of a value searched in decoded form. The clear-text search always covers all of it; past
 *  this bound an encoded secret is left to Layer 1 and to attribution (which flags its own bounds). */
export const SECRET_DECODE_CHARS = 32 * 1024;

/** The rule of the first credential found in `value`, or undefined. `step` runs before each decoded
 *  variant is searched (the policy engine uses it to enforce its deadline). */
export function secretRuleIn(value: string, step?: () => void): string | undefined {
  const clear = findSecrets(value)[0] ?? findSecrets(fold(value))[0];
  if (clear) return clear.rule;
  for (const v of decodeVariants(value.slice(0, SECRET_DECODE_CHARS), SECRET_DECODE_LIMITS).variants) {
    step?.();
    const hit = findSecrets(fold(v.text))[0];
    if (hit) return hit.rule;
  }
  return undefined;
}
