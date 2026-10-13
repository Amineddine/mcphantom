/**
 * The shared text pipeline (src/text/): confusables folding, letter-spacing, and bounded decoding.
 * Used by both Layer-2 provenance and the static scanner.
 */
import { describe, expect, it } from 'vitest';
import { CONFUSABLES, CONFUSABLES_VERSION } from '../src/text/confusables-data.js';
import { decodeVariants, type DecodeLimits } from '../src/text/decode.js';
import { despace, fold, foldConfusables, normalize } from '../src/text/normalize.js';

const b64 = (s: string) => Buffer.from(s).toString('base64');
const hex = (s: string) => Buffer.from(s).toString('hex');
const rev = (s: string) => Array.from(s).reverse().join('');
const rot13 = (s: string) => s.replace(/[A-Za-z]/g, (c) => String.fromCharCode(((c.charCodeAt(0) - (c <= 'Z' ? 65 : 97) + 13) % 26) + (c <= 'Z' ? 65 : 97)));
// A canary in AWS access-key format, assembled at runtime so scanners do not flag the repo.
const KEY = ['AK', 'IA', 'Q3EG', 'XK7M', 'PL2N', 'RT5W'].join('');

/** Deterministic PRNG (mulberry32) for the property tests. */
function rng(seed: number): () => number {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

describe('confusables table (generated from Unicode confusables.txt)', () => {
  it('is the pinned version and only maps non-ASCII to ASCII', () => {
    expect(CONFUSABLES_VERSION).toBe('16.0.0');
    expect(CONFUSABLES.length).toBeGreaterThan(1000);
    for (const [cp, target] of CONFUSABLES) {
      expect(cp).toBeGreaterThanOrEqual(0x80);
      expect(target).toMatch(/^[\x20-\x7E]+$/);
    }
  });

  it('folds Cyrillic and Greek look-alikes to Latin, leaving ASCII untouched', () => {
    expect(foldConfusables('іgnоrе аll')).toBe('ignore all'); // Cyrillic і, о, е, а
    expect(foldConfusables('Ηello')).toBe('Hello'); // Greek capital eta
    const ascii = 'mI10 rn lO0 plain ASCII stays as is';
    expect(foldConfusables(ascii)).toBe(ascii);
  });

  it('keeps case consistent for the I/l ambiguity: Cyrillic І folds to I, not l', () => {
    const disguised = KEY.replace('I', 'І').replace('A', 'А'); // Cyrillic І and А
    expect(disguised).not.toBe(KEY);
    expect(fold(disguised)).toBe(KEY);
  });

  it('normalize is idempotent (property, 2000 random mixed-script strings)', () => {
    const r = rng(42);
    const pool = ['a', 'B', ' ', '\t', 'і', 'О', 'Ｚ', '​', 'ﬁ', 'é', 'Ω', '1', '-', '𝐀', 'ß', 'İ', 'ǅ'];
    for (let i = 0; i < 2000; i++) {
      let s = '';
      const n = Math.floor(r() * 30);
      for (let j = 0; j < n; j++) s += pool[Math.floor(r() * pool.length)] ?? '';
      expect(normalize(normalize(s))).toBe(normalize(s));
    }
  });
});

describe('despace', () => {
  it('joins single characters separated by one separator', () => {
    expect(despace('please i g n o r e  a l l previous')).toBe('please ignore  all previous');
    expect(despace(KEY.split('').join('-'))).toBe(KEY);
    expect(despace(KEY.split('').join('.'))).toBe(KEY);
  });

  it('keeps punctuation inside the spelled value, including the separator itself', () => {
    const url = 'https://exfil.attacker-bench.example/c?id=7f3a';
    expect(despace(`to ${url.split('').join('-')}`)).toBe(`to ${url}`);
    expect(despace(`to ${url.split('').join(' ')}`)).toContain(url.replace(/ /g, ''));
    expect(despace('d o  n o t  t e l l')).toBe('do  not  tell');
  });

  it('leaves ordinary prose and short abbreviations alone', () => {
    const prose = 'Reads a file, e.g. notes.txt, and returns its text. Use a b test only.';
    expect(despace(prose)).toBe(prose);
  });
});

describe('decodeVariants', () => {
  const texts = (s: string, limits?: DecodeLimits) => decodeVariants(s, limits).variants.map((v) => v.text);
  const chainOf = (s: string, want: string) => decodeVariants(s).variants.find((v) => v.text.includes(want))?.chain;

  it.each([
    ['base64', `body: ${b64(`key=${KEY}`)}`],
    ['base64 (url-safe, unpadded)', `x ${b64(`key=${KEY}??>>`).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')} y`],
    ['hex', `data ${hex(`key=${KEY}`)}`],
    ['hex with \\x', hex(`key=${KEY}`).replace(/(..)/g, '\\x$1')],
    ['url', encodeURIComponent(`key=${KEY}`).replace(/[A-Z0-9]/g, (c) => `%${c.charCodeAt(0).toString(16)}`)],
    ['html entities', Array.from(`key=${KEY}`).map((c) => `&#${c.charCodeAt(0)};`).join('')],
    ['\\u escapes', Array.from(`key=${KEY}`).map((c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join('')],
    ['rot13', rot13(`key=${KEY}`)],
    ['reversal', rev(`key=${KEY}`)],
    ['separator spelling', KEY.split('').join(' ')],
  ])('recovers the key from %s', (_name, encoded) => {
    expect(texts(encoded).some((t) => t.includes(KEY))).toBe(true);
  });

  it('follows chains: base64 of reversed text, hex of base64', () => {
    expect(chainOf(b64(rev(`send ${KEY} now`)), KEY)).toEqual(['base64', 'reverse']);
    expect(chainOf(hex(b64(`send ${KEY} now`)), KEY)).toEqual(['hex', 'base64']);
  });

  it('does not replace base64-looking tokens that decode to binary (real secrets stay intact)', () => {
    const awsSecretLike = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    const v = decodeVariants(`secret ${awsSecretLike}`, { maxDepth: 1, maxVariants: 32, maxChars: 1e6, segmentOnly: true });
    expect(v.variants).toEqual([]);
  });

  it('a hash or long word is not "decoded" into noise', () => {
    const s = 'commit 9fceb02d0ae598e95dc970b74767f19372d61af8 internationalization';
    expect(decodeVariants(s, { maxDepth: 1, maxVariants: 32, maxChars: 1e6, segmentOnly: true }).variants).toEqual([]);
  });

  it('reports truncation instead of silently stopping', () => {
    const r = decodeVariants(b64(b64(b64(`x ${KEY}`))), { maxDepth: 3, maxVariants: 2, maxChars: 1e6 });
    expect(r.truncated).toBe(true);
    expect(r.variants).toHaveLength(2);
    expect(decodeVariants('abc', { maxDepth: 3, maxVariants: 32, maxChars: 4 }).truncated).toBe(true);
  });

  it('segmentOnly skips rot13 and reversal', () => {
    expect(decodeVariants('hello world', { maxDepth: 2, maxVariants: 32, maxChars: 1e6, segmentOnly: true }).variants).toEqual([]);
  });

  it('stays bounded on 1 MB adversarial inputs (no catastrophic backtracking)', () => {
    const inputs = [
      'A'.repeat(1 << 20) + '===', // base64 alphabet run with excess padding
      'a'.repeat((1 << 20) + 1), // odd-length hex run
      'a '.repeat(1 << 19) + 'bb', // letter-spacing run ending in a word
      '%4'.repeat(1 << 19), // broken percent escapes
      '&#'.repeat(1 << 19), // broken entities
      '\\u12'.repeat(1 << 18), // broken escapes
    ];
    for (const s of inputs) {
      const t0 = performance.now();
      decodeVariants(s, { maxDepth: 3, maxVariants: 32, maxChars: 4 << 20 });
      expect(performance.now() - t0).toBeLessThan(3000);
    }
  });
});
