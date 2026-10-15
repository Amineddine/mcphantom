import { isUtf8 } from 'node:buffer';
import { despace } from './normalize.js';

/**
 * Bounded generator of decoded variants of a string, shared by Layer-2 provenance and the scanner.
 *
 * Two kinds of decoder:
 *  - *segment* decoders find encoded runs inside surrounding text and replace each run that decodes to
 *    plausible text (base64, hex) or apply an unambiguous textual escape (URL %XX, HTML entities,
 *    `\u`/`\x` escapes, letter spacing);
 *  - *whole-string* transforms that cannot be recognised from their output (rot13, reversal). With
 *    `wholeOn: 'tokens'` they run only over the whitespace-free tokens of ≥ 8 characters, which is
 *    where every identifier we track lives (keys, URLs, addresses): prose shrinks to a fraction, so
 *    attribution stays cheap. The scanner uses `'text'`, since an instruction is a whole sentence.
 *
 * Variants are explored breadth-first, so chains like base64(reverse(x)) are found, within hard limits on
 * depth, number of variants and total bytes produced. Hitting a limit is reported (`truncated`), never
 * silent: the caller marks its decision `attributionDegraded`.
 */

export type Decoder = 'base64' | 'hex' | 'url' | 'html' | 'escape' | 'despace' | 'rot13' | 'reverse';

export interface Variant {
  text: string;
  /** Decoders applied to the original, in order. */
  chain: Decoder[];
}

export interface DecodeLimits {
  /** Maximum chain length. */
  maxDepth: number;
  /** Maximum number of variants returned (the original is not counted). */
  maxVariants: number;
  /** Maximum total characters across all variants produced. */
  maxChars: number;
  /** Skip the whole-string transforms (rot13, reversal). */
  segmentOnly?: boolean;
  /** What the whole-string transforms apply to: the full text (default) or only its candidate tokens. */
  wholeOn?: 'text' | 'tokens';
}

export const DEFAULT_DECODE_LIMITS: DecodeLimits = { maxDepth: 3, maxVariants: 32, maxChars: 256 * 1024 };

export interface DecodeResult {
  variants: Variant[];
  /** True if a limit stopped exploration before every reachable variant was produced. */
  truncated: boolean;
}

export function decodeVariants(input: string, limits: DecodeLimits = DEFAULT_DECODE_LIMITS): DecodeResult {
  const seen = new Set<string>([input]);
  const variants: Variant[] = [];
  let chars = 0;
  const state: DecodeState = { segmentTries: MAX_SEGMENT_TRIES, truncated: false };
  let frontier: Variant[] = [{ text: input, chain: [] }];
  for (let depth = 0; depth < limits.maxDepth && frontier.length > 0; depth++) {
    const next: Variant[] = [];
    for (const v of frontier) {
      for (const [name, fn] of DECODERS) {
        if (limits.segmentOnly && WHOLE.has(name)) continue;
        // A whole-string transform directly after another one is skipped: rot13∘rot13 and
        // reverse∘reverse are the identity, and rot13∘reverse only re-orders work already covered.
        if (WHOLE.has(name) && WHOLE.has(v.chain[v.chain.length - 1] as Decoder)) continue;
        const out = fn(WHOLE.has(name) && limits.wholeOn === 'tokens' ? tokensOf(v.text) : v.text, state);
        if (out === undefined || seen.has(out)) continue;
        if (variants.length >= limits.maxVariants || chars + out.length > limits.maxChars) {
          return { variants, truncated: true };
        }
        seen.add(out);
        chars += out.length;
        const nv = { text: out, chain: [...v.chain, name] };
        variants.push(nv);
        next.push(nv);
      }
    }
    frontier = next;
  }
  return { variants, truncated: state.truncated };
}

/** Per-call budget shared by the decoders (only the base64 path-segment split uses one). */
interface DecodeState {
  segmentTries: number;
  truncated: boolean;
}

/**
 * Path segments tried one by one per `decodeVariants` call. Each try is cheap (~1.5 µs) but a hostile
 * 128 KiB body of slash-joined runs has thousands; past the budget, segments are not split and the
 * result is reported `truncated` (6b PR 6, measured with `bench:policy`).
 */
export const MAX_SEGMENT_TRIES = 256;

// -------------------------------------------------------------------------------------------------
// Decoders. Each returns the transformed string, or undefined if it does not apply.

const WHOLE: ReadonlySet<Decoder> = new Set(['rot13', 'reverse']);

/** Whitespace-free runs of ≥ 8 characters, space-joined: where identifiers can be. */
function tokensOf(s: string): string {
  if (!/\s/.test(s)) return s;
  return s.match(/\S{8,}/g)?.join(' ') ?? '';
}

const DECODERS: [Decoder, (s: string, state: DecodeState) => string | undefined][] = [
  ['base64', decodeBase64Segments],
  ['hex', decodeHexSegments],
  ['url', decodeUrlEscapes],
  ['html', decodeHtmlEntities],
  ['escape', decodeBackslashEscapes],
  ['despace', (s) => changed(s, despace(s))],
  ['rot13', rot13],
  ['reverse', reverse],
];

function changed(before: string, after: string): string | undefined {
  return after === before ? undefined : after;
}

/**
 * Decoded bytes count as text only if they are valid UTF-8 and almost entirely printable. Real secrets
 * look like base64 (an AWS secret key is 40 base64 characters); decoding one yields binary noise, which
 * this rejects, so the original token is left in place for the identifier matchers.
 */
function plausibleText(bytes: Buffer): string | undefined {
  if (bytes.length === 0) return undefined;
  // Validated without throwing: most candidate runs are not base64 text, and a throwing strict decoder
  // cost an exception per run (17x slower on slash-joined runs once path segments were tried; 6b PR 6).
  if (!isUtf8(bytes)) return undefined;
  const text = bytes.toString('utf8');
  // Count characters that are neither letters, numbers, punctuation, symbols nor ordinary whitespace.
  const noise = text.match(/[^\p{L}\p{N}\p{P}\p{S}\p{Zs}\t\n\r]/gu)?.length ?? 0;
  const total = text.length;
  return noise / total <= 0.1 ? text : undefined;
}

/** Standard and URL-safe base64 runs of ≥ 12 characters (9 decoded bytes), padding optional. */
const BASE64_RUN = /(?<![A-Za-z0-9+/\-_])[A-Za-z0-9+/\-_]{12,}={0,2}(?![A-Za-z0-9+/\-_=])/g;

function decodeBase64Segments(s: string, state: DecodeState): string | undefined {
  const out = s.replace(BASE64_RUN, (run: string, at: number) => {
    const whole = decodeBase64Run(run);
    if (whole !== undefined) return isolate(whole, s, at, run.length);
    // `/` is in the standard alphabet, so a URL path joins its segments into one run (`9/i/<b64url>`)
    // that decodes to noise. Each segment is tried on its own (6b PR 6: base64 in a URL path segment).
    // Only segments mixing upper and lower case are tried: base64 of printable text practically always
    // does, ordinary path words (`thumbnail_large_2`) do not.
    if (!run.includes('/')) return run;
    const parts = run.split('/');
    const decoded = parts.map((p) => {
      if (p.length < 12 || !/[A-Z]/.test(p) || !/[a-z]/.test(p)) return undefined;
      if (state.segmentTries <= 0) {
        state.truncated = true;
        return undefined;
      }
      state.segmentTries--;
      return decodeBase64Run(p);
    });
    if (decoded.every((d) => d === undefined)) return run;
    return isolate(parts.map((p, i) => (decoded[i] === undefined ? p : ` ${decoded[i]} `)).join('/').trim(), s, at, run.length);
  });
  return changed(s, out);
}

function decodeBase64Run(run: string): string | undefined {
  const body = run.replace(/=+$/, '');
  if (body.length % 4 === 1) return undefined; // not a valid base64 length
  if (/[+/]/.test(body) && /[-_]/.test(body)) return undefined; // mixed alphabets
  return plausibleText(Buffer.from(body.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
}

/**
 * Decoded text spliced into its surroundings fuses with them (`?d=` + a token, a URL + `.png`), and the
 * identifier extractors then take the wrong span. A space is added on each side that touches a
 * non-space character (6b PR 6; before, only pattern-detected secrets and e-mails survived in a URL).
 */
function isolate(text: string, s: string, at: number, len: number): string {
  const before = at > 0 && !/\s/.test(s[at - 1] ?? '') ? ' ' : '';
  const after = at + len < s.length && !/\s/.test(s[at + len] ?? '') ? ' ' : '';
  return before + text + after;
}

/** Hex runs of ≥ 16 digits (8 bytes), optionally `0x`-prefixed or `\x`/space/colon separated pairs. */
const HEX_RUN = /(?<![0-9A-Fa-f])(?:0x)?(?:[0-9A-Fa-f]{2}(?:[ :]|\\x)?){8,}(?![0-9A-Fa-f])/g;

function decodeHexSegments(s: string): string | undefined {
  const out = s.replace(HEX_RUN, (run) => {
    const digits = run.replace(/^0x/, '').replace(/\\x|[ :]/g, '');
    if (digits.length % 2 !== 0) return run;
    const text = plausibleText(Buffer.from(digits, 'hex'));
    if (text === undefined) return run;
    return text;
  });
  return changed(s, out);
}

/** Percent-escapes, including `+` for space inside an escaped string. Malformed sequences are kept. */
function decodeUrlEscapes(s: string): string | undefined {
  if (!/%[0-9A-Fa-f]{2}/.test(s)) return undefined;
  const out = s.replace(/(?:%[0-9A-Fa-f]{2})+/g, (run) => {
    try {
      return decodeURIComponent(run);
    } catch {
      return run;
    }
  });
  return changed(s, out);
}

const NAMED_ENTITIES: Record<string, string> = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', sol: '/', colon: ':', period: '.',
  commat: '@', equals: '=', quest: '?', num: '#', percnt: '%', lowbar: '_', hyphen: '-', dash: '-',
};

function decodeHtmlEntities(s: string): string | undefined {
  if (!s.includes('&')) return undefined;
  const out = s.replace(/&(?:#(\d{1,7})|#[xX]([0-9A-Fa-f]{1,6})|([A-Za-z]{2,8}));?/g, (m, dec?: string, hex?: string, name?: string) => {
    const cp = dec !== undefined ? Number(dec) : hex !== undefined ? parseInt(hex, 16) : undefined;
    if (cp !== undefined) return cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
    return NAMED_ENTITIES[name?.toLowerCase() ?? ''] ?? m;
  });
  return changed(s, out);
}

/** `\uXXXX`, `\u{X…}`, `\xXX` (as in JSON, JS and Python string literals). */
function decodeBackslashEscapes(s: string): string | undefined {
  if (!s.includes('\\')) return undefined;
  const out = s.replace(/\\u\{([0-9A-Fa-f]{1,6})\}|\\u([0-9A-Fa-f]{4})|\\x([0-9A-Fa-f]{2})/g, (m, braced?: string, u4?: string, x2?: string) => {
    const cp = parseInt(braced ?? u4 ?? x2 ?? '', 16);
    return Number.isFinite(cp) && cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
  });
  return changed(s, out);
}

// rot13 and reversal run over UTF-16 code units in a typed array: an order of magnitude faster on
// large inputs than string building, and these are the only transforms applied to whole strings.
const UTF16 = new TextDecoder('utf-16le');

function rot13(s: string): string | undefined {
  if (!/[A-Za-z]/.test(s)) return undefined;
  const u = new Uint16Array(s.length);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    u[i] = c >= 65 && c <= 90 ? ((c - 52) % 26) + 65 : c >= 97 && c <= 122 ? ((c - 84) % 26) + 97 : c;
  }
  return UTF16.decode(u);
}

/** Code-point-safe reversal: a surrogate pair is kept in order. */
function reverse(s: string): string | undefined {
  const n = s.length;
  if (n < 2) return undefined;
  const u = new Uint16Array(n);
  for (let i = 0; i < n; i++) {
    const c = s.charCodeAt(i);
    const d = i + 1 < n ? s.charCodeAt(i + 1) : 0;
    if (c >= 0xd800 && c <= 0xdbff && d >= 0xdc00 && d <= 0xdfff) {
      u[n - i - 2] = c;
      u[n - i - 1] = d;
      i++;
    } else {
      u[n - i - 1] = c;
    }
  }
  return changed(s, UTF16.decode(u));
}
