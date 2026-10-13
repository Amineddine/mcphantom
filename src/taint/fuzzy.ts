import { normalize } from '../text/normalize.js';

/**
 * Winnowing fingerprints (Schleimer, Wilkerson, Aiken — "Winnowing: local algorithms for document
 * fingerprinting", SIGMOD 2003) for the Layer-2 `fuzzy` matcher: text copied with light edits or
 * reordering still shares most of its k-grams with the source.
 *
 * Text is normalized and reduced to letters and digits, so whitespace, punctuation, case, width and
 * look-alike changes do not matter. Every k-gram is hashed; in each window of W consecutive hashes the
 * minimum is kept. Guarantee: any shared run of at least W + K - 1 reduced characters yields at least
 * one shared fingerprint. Expected density is 2 / (W + 1) fingerprints per character.
 */
export const K = 12;
export const W = 16;

/** Reduced form: normalized, letters and digits only. Pass `normalized` when `s` already is. */
export function reduce(s: string, normalized = false): string {
  const t = normalized ? s : normalize(s);
  let out = '';
  let start = -1;
  // Copy runs of kept characters in slices; ASCII is classified by code, the rest by Unicode property.
  for (let i = 0; i < t.length; i++) {
    const c = t.charCodeAt(i);
    const keep = c < 0x80 ? (c >= 48 && c <= 57) || (c >= 97 && c <= 122) || (c >= 65 && c <= 90) : LETTER_OR_DIGIT.test(t[i] as string);
    if (keep && start < 0) start = i;
    else if (!keep && start >= 0) {
      out += t.slice(start, i);
      start = -1;
    }
  }
  return start >= 0 ? out + t.slice(start) : out;
}

const LETTER_OR_DIGIT = /[\p{L}\p{N}]/u;

/** Polynomial rolling-hash base (odd) and BASE^(K-1) mod 2^32. */
const BASE = 0x01000193;
const TOP = (() => {
  let p = 1;
  for (let i = 0; i < K - 1; i++) p = Math.imul(p, BASE);
  return p;
})();

/** Sorted, de-duplicated winnowed fingerprints of `s` (32-bit hashes). */
export function fingerprints(s: string, normalized = false): Uint32Array {
  const t = reduce(s, normalized);
  const n = t.length - K + 1;
  if (n <= 0) return new Uint32Array(0);
  const hashes = new Uint32Array(n);
  // Rabin–Karp rolling hash over UTF-16 code units, modulo 2^32.
  let h = 0;
  for (let j = 0; j < K; j++) h = (Math.imul(h, BASE) + t.charCodeAt(j)) | 0;
  hashes[0] = h >>> 0;
  for (let i = 1; i < n; i++) {
    h = (Math.imul(h - Math.imul(t.charCodeAt(i - 1), TOP), BASE) + t.charCodeAt(i + K - 1)) | 0;
    hashes[i] = h >>> 0;
  }
  // Sliding-window minimum with a monotonic deque of indices; record the rightmost minimum of each
  // window when it changes (the standard winnowing selection).
  const picked: number[] = [];
  const deque = new Int32Array(n);
  let head = 0;
  let tail = 0;
  let last = -1;
  for (let i = 0; i < n; i++) {
    const h = hashes[i] as number;
    while (tail > head && (hashes[deque[tail - 1] as number] as number) >= h) tail--;
    deque[tail++] = i;
    if ((deque[head] as number) <= i - W) head++;
    if (i >= W - 1 || i === n - 1) {
      const m = deque[head] as number;
      if (m !== last) {
        picked.push(hashes[m] as number);
        last = m;
      }
    }
  }
  const sorted = Uint32Array.from(picked).sort();
  let w = 0;
  for (let i = 0; i < sorted.length; i++) if (i === 0 || sorted[i] !== sorted[i - 1]) sorted[w++] = sorted[i] as number;
  return sorted.slice(0, w);
}

function has(sorted: Uint32Array, v: number): boolean {
  let lo = 0;
  let hi = sorted.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    const x = sorted[mid] as number;
    if (x === v) return true;
    if (x < v) lo = mid + 1;
    else hi = mid - 1;
  }
  return false;
}

/** Shared fingerprints and the fraction of `needle`'s fingerprints found in `haystack`. */
export function containment(needle: Uint32Array, haystack: Uint32Array): { shared: number; score: number } {
  if (needle.length === 0 || haystack.length === 0) return { shared: 0, score: 0 };
  let shared = 0;
  for (const v of needle) if (has(haystack, v)) shared++;
  return { shared, score: shared / needle.length };
}
