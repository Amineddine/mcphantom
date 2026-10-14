#!/usr/bin/env node
/**
 * Generates src/text/confusables-data.ts from Unicode's confusables.txt (UTS #39 security data).
 *
 *   curl -sSfLo confusables.txt https://www.unicode.org/Public/security/16.0.0/confusables.txt
 *   node scripts/gen-confusables.mjs confusables.txt
 *
 * Only a subset is kept, on purpose: mappings from a NON-ASCII code point to a target made entirely of
 * ASCII. MCPhantom folds look-alikes *into* Latin so that English instruction patterns and ASCII
 * identifiers (keys, URLs) match; it never remaps ASCII itself. The full TR39 skeleton also maps ASCII
 * (`m` → `rn`, `I` → `l`, `0` → `O`), which is right for comparing two skeletons but would break every
 * pattern written against ordinary text.
 *
 * The data is © Unicode, Inc., Unicode License v3 (see NOTICE). The generated file records the source
 * version and SHA-256 so a regeneration is reviewable. Parsing and rendering live in
 * confusables-lib.mjs (tested by test/confusables-gen.test.ts).
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseConfusables, renderConfusables } from './confusables-lib.mjs';

const src = process.argv[2];
if (!src) {
  process.stderr.write('usage: node scripts/gen-confusables.mjs <confusables.txt>\n');
  process.exit(2);
}
const parsed = parseConfusables(fs.readFileSync(src));
const here = path.dirname(fileURLToPath(import.meta.url));
const dest = path.join(here, '..', 'src', 'text', 'confusables-data.ts');
fs.mkdirSync(path.dirname(dest), { recursive: true });
fs.writeFileSync(dest, renderConfusables(parsed));
process.stdout.write(`wrote ${dest}: ${parsed.entries.length} mappings from confusables.txt ${parsed.version}\n`);
