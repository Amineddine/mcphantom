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
 * Letter-spacing undone: a run of three or more single letters/digits, each separated by exactly one
 * separator character (space, `-`, `_`, `.`, `·`, `•`, `|`, `/`, `,`, `*`), is joined. A wider gap
 * (two spaces) ends the run, so "i g n o r e  a l l" → "ignore  all". Multi-character separators
 * (", " or " - ") are not undone — documented in the evasion benchmark.
 */
export function despace(s: string): string {
  return s.replace(/(?<![\p{L}\p{N}])[\p{L}\p{N}](?:[ \-_.·•|/,*][\p{L}\p{N}]){2,}(?![\p{L}\p{N}])/gu, (run) => run.replace(/[ \-_.·•|/,*]/g, ''));
}
