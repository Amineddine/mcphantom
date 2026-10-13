import { CONFUSABLES } from './confusables-data.js';

/**
 * The shared canonicalisation used by Layer-2 provenance and the static scanner, so a disguise is
 * undone in one place for both.
 *
 *  - `fold`: NFKC (fullwidth → ASCII, ligatures, mathematical letters), format characters removed
 *    (zero-width, bidi controls, soft hyphen, tag characters), cross-script look-alikes folded to
 *    Latin (Cyrillic «а» → "a"). Case is preserved so case-sensitive secret detectors still apply.
 *  - `normalize`: `fold`, then case-folded and whitespace collapsed — the form used for comparisons.
 *  - `despace`: undoes letter spacing ("i g n o r e", "A-K-I-A").
 */

/**
 * Non-ASCII look-alike → ASCII. Built from the generated Unicode table with one correction: UTS #39
 * skeletons map both Latin `I` and `l` to `l`, so the table sends Cyrillic `І` (U+0406) to "l". We do
 * not remap ASCII, so that would turn a disguised `AKIA…` key into `AKlA…`. An uppercase source whose
 * lowercase form folds to "i" therefore folds to "I".
 */
const CONFUSABLE_MAP: ReadonlyMap<string, string> = (() => {
  const m = new Map<string, string>();
  for (const [cp, target] of CONFUSABLES) m.set(String.fromCodePoint(cp), target);
  for (const [ch, target] of m) {
    const lower = ch.toLowerCase();
    if (target === 'l' && lower !== ch && m.get(lower) === 'i') m.set(ch, 'I');
  }
  return m;
})();

const NON_ASCII = /[\u0080-\u{10FFFF}]/u;

/** Folds cross-script look-alikes to their ASCII prototype; ASCII is never changed. */
export function foldConfusables(s: string): string {
  if (!NON_ASCII.test(s)) return s;
  let out = '';
  for (const ch of s) out += ch.charCodeAt(0) < 0x80 ? ch : (CONFUSABLE_MAP.get(ch) ?? ch);
  return out;
}

/** NFKC + format characters removed + look-alikes folded; case preserved. */
export function fold(s: string): string {
  return foldConfusables(s.normalize('NFKC').replace(/[\p{Cf}͏ᅟᅠㅤﾠ]/gu, ''));
}

/** Canonical form for matching: `fold`, case-folded, whitespace collapsed. */
export function normalize(s: string): string {
  return fold(s)
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Letter-spacing / separator spelling undone: a run of three or more single characters, each separated
 * by the same one-character separator, is joined — "i g n o r e", "g-h-p-_-x-y", "h.t.t.p.s.:./././".
 * An element is any non-whitespace character other than the separator, so punctuation inside a token,
 * URL or address survives. A wider gap (two spaces) ends a run: "i g n o r e  a l l" → "ignore  all".
 * Two-letter words in letter-spaced text ("d o  n o t") are joined only next to such a word gap, so
 * ordinary prose ("use a b test", "e.g.") is left alone. Multi-character separators (", ", " - ") and
 * mixed separators are not undone — published in the evasion benchmark.
 */
export function despace(s: string): string {
  let out = s;
  // A whitespace-bounded run is parsed by parity first, so the separator may itself be an element
  // ("a-t-t-a-c-k-e-r---b-e-n-c-h": the spelled value contains a hyphen).
  for (const re of PARITY_RUNS) out = out.replace(re, (run) => joinRun(run));
  for (const re of SEPARATOR_RUNS) out = out.replace(re, (run) => joinRun(run));
  return out.replace(SPACED_PAIR, (run) => run.replace(' ', ''));
}

const SEPARATORS = [' ', '-', '_', '.', '·', '•', '|', '/', ',', '*', ':', '+', '~'];

const SEPARATOR_RUNS: readonly RegExp[] = SEPARATORS.map((sep) => {
  // Escaped differently inside a character class (where `-` is special) and outside (where `.*+|/` are).
  const inClass = sep.replace(/[\\\]^-]/g, '\\$&');
  const outside = sep.replace(/[.*+?|/\\()[\]{}^$]/g, '\\$&');
  const el = `[^\\s${inClass}]`;
  return new RegExp(`(?<!${el})(?:${el}${outside}){2,}${el}(?!${el})`, 'gu');
});

/** Whitespace-bounded runs where every other character is the separator (any non-space elements). */
const PARITY_RUNS: readonly RegExp[] = SEPARATORS.filter((sep) => sep !== ' ').map((sep) => {
  const outside = sep.replace(/[.*+?|/\\()[\]{}^$]/g, '\\$&');
  return new RegExp(`(?<!\\S)(?:\\S${outside}){2,}\\S(?!\\S)`, 'gu');
});

/** Exactly two single characters separated by one space, next to a two-space word gap or an edge. */
const SPACED_PAIR = /(?:(?<=^|\s\s)\S \S(?!\S))|(?:(?<!\S)\S \S(?=\s\s|$))/gu;

/** Removes the separator of a run: every other character, starting with the second. */
function joinRun(run: string): string {
  const chars = Array.from(run);
  let out = '';
  for (let i = 0; i < chars.length; i += 2) out += chars[i] ?? '';
  return out;
}
