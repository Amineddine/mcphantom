/**
 * Entropy-based "possible secret" detection (DESIGN.md §2, Secrets; Phase 6b).
 *
 * The known-format rules in detectors.ts miss a random token with no prefix and no keyword next to it.
 * This finds such tokens by shape and entropy. It cannot tell a secret from a random identifier by the
 * token alone: UUIDs, commit SHAs, digests, database ids and document ids look exactly like keys. So, by
 * owner decision, a hit here never raises the session label to `secret` on its own. Hits are redacted in
 * logs and recorded as "possible secret"; whether they raise the label is a configuration choice
 * (`secrets.entropy.on_hit`, default `record`). Measured on benign tool outputs by `npm run bench:entropy`.
 *
 * Two shapes are distinguished:
 *  - `id` (identifier-shaped): hex strings, UUIDs, SRI integrity values, type-prefixed ids (`card_…`,
^ *    `WFR_…`), and any token whose field name says it is an identifier (`"id":`, `request_id=`,
 *    `VersionId`, `etag`, `keyid`, …). Only ever recorded, whatever `on_hit` says. Published misses:
 *    a hex-encoded secret, an unknown vendor's prefixed key, and a secret stored under an id-named field
 *    (a field name that also says secret/token/password/credential/auth is never treated as an id).
 *  - `random`: everything else that passes the shape and entropy tests. Only these can escalate.
 *
 * Linear time: one character-class scan, then per-token work bounded by MAX_TOKEN and a 64-character
 * look-behind for the field name.
 */
export type EntropyShape = 'random' | 'id';

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
/** A typed hex id such as `ami-0abc…` or `subnet-0abc…`: a short lowercase word, a separator, hex. */
const PREFIXED_HEX_RE = /^[a-z]{2,12}[-_][0-9a-fA-F]{8,}$/;
/** A type-prefixed object id: `card_…`, `dpl_…`, GitHub node ids (`WFR_…`, `CS_…`, `REF_…`). Known
 *  vendors' prefixed *secrets* (ghp_, sk_live_, xoxb-, npm_, phx_, …) are matched by detectors.ts
 *  first and never reach this classification. */
const PREFIXED_ID_RE = /^(?:[a-z]{2,8}|[A-Z]{1,5})_[A-Za-z0-9][A-Za-z0-9_-]{7,}$/;

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

/** Shape of a token on its own (no context), or undefined if it is not a possible secret. */
export function classifyToken(token: string): EntropyShape | undefined {
  if (token.length < MIN_TOKEN || token.length > MAX_TOKEN) return undefined;
  if (UUID_RE.test(token) || SRI_RE.test(token)) return 'id';
  if (HEX_RE.test(token) || PREFIXED_HEX_RE.test(token)) return entropy(token) >= 3 ? 'id' : undefined;
  const t = token.replace(/=+$/, '');
  const lower = /[a-z]/.test(t);
  const upper = /[A-Z]/.test(t);
  const digit = /[0-9]/.test(t);
  if (!digit || !(lower || upper)) return undefined;
  if (entropy(t) < entropyThreshold(t.length)) return undefined;
  return PREFIXED_ID_RE.test(token) ? 'id' : 'random';
}

/** A path or name component that is a word, not random: four or more letters with a vowel, lowercase,
 *  capitalised or camelCase (`billing`, `Replica`, `ReplicaSet`). */
const WORD_RE = /^(?=[A-Za-z]{4,}$)[A-Z]?[a-z]+(?:[A-Z][a-z]+)*$/;
const VOWEL_RE = /[aeiou]/;
const isWord = (s: string): boolean => WORD_RE.test(s) && VOWEL_RE.test(s);

/**
 * Splits a character run into the tokens a human would see. `key=value` is split at an inner `=`
 * (base64 padding only ever trails). A type-prefixed id is kept whole. Otherwise a run with `/`, `-` or
 * `_` separators is split at them when one of its components is a word (`exports/billing/<uuid>`,
 * `reports-oh5yspwmkg-kwlb7`): random base64 also contains these characters, but its components are
 * almost never words.
 */
function tokens(run: string, offset: number, out: { text: string; start: number }[], depth = 0): void {
  const inner = /=+(?=[^=])/.exec(run);
  if (inner) {
    tokens(run.slice(0, inner.index), offset, out, depth);
    const rest = inner.index + inner[0].length;
    tokens(run.slice(rest), offset + rest, out, depth);
    return;
  }
  if (depth < 3 && !PREFIXED_ID_RE.test(run)) {
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

/**
 * The field name a value is assigned to, from the text just before it: `"id": "`, `request_id=`,
 * `x-request-id: `, `VersionId: `, `"keyid":"SHA256:`. Undefined when there is none.
 */
const FIELD_BEFORE_RE = /([A-Za-z][A-Za-z0-9_.-]{0,40})["']?\s{0,4}[:=]\s{0,4}["'(]?(?:[A-Za-z0-9]{1,10}:)?$/;
/** Field names that say "identifier": `id`, `*_id`, `*-id`, `*Id`, `uid`, `uuid`, `etag`, `sig`, ... */
const ID_FIELD_RE = /(?:^|[_.-])(?:id|ids|uid|uuid|guid|etag|sig|digest|hash|sha\d*|checksum|integrity|cursor|slug|oid)$|^(?:id|uid|etag|sig|keyid)$|[a-z0-9](?:Id|ID|Ids|Uid|UID|Hash|Etag)$/i;
/** A field name that also says the value is a credential is never treated as an identifier. */
const SECRET_FIELD_RE = /secret|token|passw|pwd|credential|auth|private|api[_-]?key/i;

function fieldBefore(text: string, start: number): string | undefined {
  return FIELD_BEFORE_RE.exec(text.slice(Math.max(0, start - 64), start))?.[1];
}

export function isIdField(field: string | undefined): boolean {
  return field !== undefined && ID_FIELD_RE.test(field) && !SECRET_FIELD_RE.test(field);
}

export function findPossibleSecrets(text: string): PossibleSecret[] {
  const out: PossibleSecret[] = [];
  for (const m of text.matchAll(RUN_RE)) {
    if (m[0].length < MIN_TOKEN) continue;
    const toks: { text: string; start: number }[] = [];
    tokens(m[0], m.index, toks);
    // A data URI's payload (`data:image/png;base64,…`) is content, not a token.
    if (text.slice(Math.max(0, m.index - 8), m.index) === ';base64,') continue;
    for (const t of toks) {
      let shape = classifyToken(t.text);
      if (shape === 'random' && isIdField(fieldBefore(text, t.start))) shape = 'id';
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
