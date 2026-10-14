/**
 * Entropy-based "possible secret" detection (DESIGN.md §2, Secrets; Phase 6b).
 *
 * The known-format rules in detectors.ts miss a random token with no prefix and no keyword next to it.
 * This finds such tokens by shape and entropy. It cannot tell a secret from a random identifier: UUIDs,
 * commit SHAs, digests, database ids and document ids look exactly like keys. So, by owner decision,
 * a hit here never raises the session label to `secret` on its own. Hits are redacted in logs and
 * recorded as "possible secret"; whether they raise the label is a configuration choice
 * (`secrets.entropy.on_hit`, default `record`). The false-positive rate is measured on benign tool
 * outputs by `npm run bench:entropy`.
 *
 * Two shapes are distinguished:
 *  - `hash`: hex strings, UUIDs and SRI integrity values. Overwhelmingly identifiers and digests, so
 *    they are only ever recorded, whatever `on_hit` says. A hex-encoded secret is therefore missed by
 *    this detector (published in the benchmark).
 *  - `random`: everything else that passes the shape and entropy tests. Only these can escalate.
 *
 * Linear time: one character-class scan, then per-token work bounded by MAX_TOKEN.
 */
export type EntropyShape = 'random' | 'hash';

export interface PossibleSecret {
  start: number;
  end: number;
  shape: EntropyShape;
}

export const MIN_TOKEN = 20;
/** Longer runs are blobs (images, archives, certificates), not tokens; PEM keys have their own rule. */
export const MAX_TOKEN = 512;

const RUN_RE = /[A-Za-z0-9_\-+/=]+/g;
const HEX_RE = /^[0-9a-fA-F]+$/;
const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const SRI_RE = /^sha(?:256|384|512)-[A-Za-z0-9+/]+=*$/;

/** Shannon entropy in bits per character. */
export function entropy(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Minimum Shannon entropy (bits/char) for a token of length `n` to count as random-looking. */
export function entropyThreshold(n: number): number {
  return 0.8 * Math.log2(Math.min(n, 64));
}

/** A typed hex id such as `ami-0abc…` or `subnet-0abc…`: a short lowercase word, a separator, hex. */
const PREFIXED_HEX_RE = /^[a-z]{2,12}[-_][0-9a-fA-F]{8,}$/;

export function classifyToken(token: string): EntropyShape | undefined {
  if (token.length < MIN_TOKEN || token.length > MAX_TOKEN) return undefined;
  if (UUID_RE.test(token) || SRI_RE.test(token)) return 'hash';
  if (HEX_RE.test(token) || PREFIXED_HEX_RE.test(token)) return entropy(token) >= 3 ? 'hash' : undefined;
  const t = token.replace(/=+$/, '');
  const lower = /[a-z]/.test(t);
  const upper = /[A-Z]/.test(t);
  const digit = /[0-9]/.test(t);
  if (!digit || !(lower || upper)) return undefined;
  if (Number(lower) + Number(upper) + Number(digit) < 2) return undefined;
  return entropy(t) >= entropyThreshold(t.length) ? 'random' : undefined;
}

/** A path or name component that is a word, not random: four or more letters with a vowel, lowercase,
 *  capitalised or camelCase (`billing`, `Replica`, `ReplicaSet`). */
const WORD_RE = /^(?=[A-Za-z]{4,}$)[A-Z]?[a-z]+(?:[A-Z][a-z]+)*$/;
const VOWEL_RE = /[aeiou]/;
const isWord = (s: string): boolean => WORD_RE.test(s) && VOWEL_RE.test(s);

/**
 * Splits a character run into the tokens a human would see. `key=value` is split at an inner `=`
 * (base64 padding only ever trails). A run with `/`, `-` or `_` separators is split at them when one
 * of its components is a word (`exports/billing/<uuid>`, `reports-oh5yspwmkg-kwlb7`): random base64
 * also contains these characters, but its components are almost never words.
 */
function tokens(run: string, offset: number, out: { text: string; start: number }[], depth = 0): void {
  const inner = /=+(?=[^=])/.exec(run);
  if (inner) {
    tokens(run.slice(0, inner.index), offset, out, depth);
    const rest = inner.index + inner[0].length;
    tokens(run.slice(rest), offset + rest, out, depth);
    return;
  }
  if (depth < 3) {
    for (const sep of ['/', '-', '_']) {
      if (!run.includes(sep)) continue;
      const parts = run.split(sep);
      if (!parts.some(isWord)) continue;
      let pos = 0;
      for (const p of parts) {
        tokens(p, offset + pos, out, depth + 1);
        pos += p.length + 1;
      }
      return;
    }
  }
  if (run.length >= MIN_TOKEN) out.push({ text: run, start: offset });
}

export function findPossibleSecrets(text: string): PossibleSecret[] {
  const out: PossibleSecret[] = [];
  for (const m of text.matchAll(RUN_RE)) {
    if (m[0].length < MIN_TOKEN) continue;
    const toks: { text: string; start: number }[] = [];
    tokens(m[0], m.index, toks);
    for (const t of toks) {
      const shape = classifyToken(t.text);
      if (shape) out.push({ start: t.start, end: t.start + t.text.length, shape });
    }
  }
  return out;
}

/** Characters of one text examined for possible secrets (the scan is linear; this bounds it anyway). */
export const MAX_ENTROPY_SCAN = 1024 * 1024;

/**
 * Possible secrets that a known-format rule did not already find (those are real `secret` hits), in
 * the first MAX_ENTROPY_SCAN characters. `known` are the known-format matches of the same text.
 */
export function possibleSecretsBeyond(text: string, known: readonly { start: number; end: number }[]): PossibleSecret[] {
  const scanned = text.length > MAX_ENTROPY_SCAN ? text.slice(0, MAX_ENTROPY_SCAN) : text;
  return findPossibleSecrets(scanned).filter((p) => !known.some((k) => p.start < k.end && p.end > k.start));
}
