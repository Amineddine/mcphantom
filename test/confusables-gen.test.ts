/**
 * 6a review, untested path 3: scripts/gen-confusables.mjs. The parser is tested on a small fixture in
 * the confusables.txt format, and the committed table is checked against the generator's invariants
 * (the 1.5 MB source file is not vendored, so a byte-for-byte regeneration is not run in CI).
 */
import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parseConfusables, renderConfusables } from '../scripts/confusables-lib.mjs';
import { CONFUSABLES, CONFUSABLES_SHA256, CONFUSABLES_VERSION } from '../src/text/confusables-data.js';

const FIXTURE = [
  '# confusables.txt',
  '# Version: 99.0.0',
  '# Date: 2099-01-01',
  '',
  '0430 ;\t0061 ;\tMA\t# ( а → a ) CYRILLIC SMALL LETTER A → LATIN SMALL LETTER A',
  '006D ;\t0072 006E ;\tMA\t# ( m → rn ) ASCII source: must be skipped',
  '0440 ;\t0070 ;\tMA\t# ( р → p ) CYRILLIC SMALL LETTER ER → LATIN SMALL LETTER P',
  '00C6 ;\t0041 0045 ;\tMA\t# ( Æ → AE ) multi-character ASCII target',
  '0251 ;\t03B1 ;\tMA\t# ( ɑ → α ) non-ASCII target: must be skipped',
  '1D400 ;\t0041 ;\tMA\t# ( 𝐀 → A ) astral source',
  '0441 ;\t0063 ;\tSL\t# ( с → c ) not an MA mapping (older file versions): must be skipped',
  '0435 ;\t0065 ;\tMA\t# ( е → e ) CRLF line ending\r',
].join('\n');

describe('gen-confusables: parser', () => {
  const parsed = parseConfusables(Buffer.from(FIXTURE, 'utf8'));

  it('reads the version and hashes the exact input bytes', () => {
    expect(parsed.version).toBe('99.0.0');
    expect(parsed.sha256).toBe(crypto.createHash('sha256').update(Buffer.from(FIXTURE, 'utf8')).digest('hex'));
  });

  it('keeps only MA mappings from non-ASCII to ASCII-only targets, sorted by code point', () => {
    expect(parsed.entries).toEqual([
      [0x00c6, 'AE'],
      [0x0430, 'a'],
      [0x0435, 'e'],
      [0x0440, 'p'],
      [0x1d400, 'A'],
    ]);
  });

  it('rejects a file without a version header', () => {
    expect(() => parseConfusables(Buffer.from('0430 ;\t0061 ;\tMA\t#\n'))).toThrow(/Version/);
  });

  it('renders a module that records version, hash and count', () => {
    const out = renderConfusables(parsed);
    expect(out).toContain("export const CONFUSABLES_VERSION = '99.0.0';");
    expect(out).toContain(`sha256 ${parsed.sha256}`);
    expect(out).toContain('(5 of the file');
    expect(out).toContain('  [0x1D400, "A"],');
  });
});

describe('gen-confusables: the committed table satisfies the generator invariants', () => {
  it('is the pinned 16.0.0 source', () => {
    expect(CONFUSABLES_VERSION).toBe('16.0.0');
    expect(CONFUSABLES_SHA256).toMatch(/^[0-9a-f]{64}$/);
  });

  it('only non-ASCII sources, only printable-ASCII targets, strictly sorted', () => {
    let prev = -1;
    for (const [source, target] of CONFUSABLES) {
      expect(source).toBeGreaterThanOrEqual(0x80);
      expect(target).toMatch(/^[\x20-\x7E]+$/);
      expect(source).toBeGreaterThan(prev);
      prev = source;
    }
  });

  it('re-rendering the committed entries reproduces the committed file', async () => {
    const fs = await import('node:fs');
    const committed = fs.readFileSync(new URL('../src/text/confusables-data.ts', import.meta.url), 'utf8');
    const rendered = renderConfusables({ version: CONFUSABLES_VERSION, sha256: CONFUSABLES_SHA256, entries: CONFUSABLES.map(([s, t]) => [s, t]) });
    expect(rendered).toBe(committed.replace(/\r\n/g, '\n'));
  });
});
