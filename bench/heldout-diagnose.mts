/**
 * Diagnosis of the held-out misses (docs/reviews/phase-7-heldout.md) — no detector is changed.
 * For each claimed miss: which rule fires if ONE token of the item is swapped for the form that rule
 * knows? Shows whether a miss is about wording. Reads the frozen set and the one run's results.
 *
 *   npx tsx bench/heldout-diagnose.mts
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { scanTool } from '../src/scanner/scan.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const set = JSON.parse(fs.readFileSync(path.join(here, 'corpus/heldout-7/heldout.json'), 'utf8')) as { items: { id: string; claimed: boolean; tool: Tool }[] };
const res = JSON.parse(fs.readFileSync(path.join(here, 'results/heldout-7.json'), 'utf8')) as { outcomes: { id: string; caught: boolean; findings: string[] }[] };
const missed = new Set(res.outcomes.filter((o) => !o.caught).map((o) => o.id));
const swaps: [string, RegExp, string][] = [
  ['<INFORMATION> → <IMPORTANT>', /<(\/?)INFORMATION>/g, '<$1IMPORTANT>'],
  ['[important] → [instructions]', /\[important\]/gi, '[instructions]'],
  ['"use this tool" → "you must use the X tool"', /\buse this tool\b/gi, 'you must use the add tool'],
  ['"Please use" → "You must use"', /\bPlease use\b/g, 'You must use'],
  ['"before execute minus operation" → "before using the sub tool"', /before execute minus operation/g, 'before using the sub tool'],
];
for (const it of set.items.filter((i) => i.claimed && missed.has(i.id))) {
  const base = scanTool(it.tool);
  const out: string[] = [`${it.id} ${it.tool.name}: original findings=${base.findings.length}`];
  for (const [label, re, rep] of swaps) {
    if (!re.test(it.tool.description ?? '')) continue;
    re.lastIndex = 0;
    const r = scanTool({ ...it.tool, description: (it.tool.description ?? '').replace(re, rep) });
    out.push(`   ${label}: ${r.flagged ? 'FLAGGED' : 'not flagged'} ${r.findings.map((f) => `${f.severity} ${f.category}: ${f.detail}`).join(' | ')}`);
  }
  process.stdout.write(out.join('\n') + '\n');
}
