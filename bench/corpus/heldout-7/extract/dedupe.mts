// Dedupe held-out candidates against every definition in bench/corpus/*.json (pre-registration):
// normalised with the scanner's own `normalize`; an overlap is an identical name + description, or an
// identical poisoned field (description for description-borne kinds, name for name collisions, the
// out-of-scope parameter's property for out-of-scope kinds). Usage: tsx dedupe.mts <repo> <work-dir>
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const [repo, work] = process.argv.slice(2) as [string, string];
const { normalize } = (await import(pathToFileURL(path.join(repo, 'src/text/normalize.ts')).href)) as { normalize: (s: string) => string };
const N = (s: unknown) => (typeof s === 'string' ? normalize(s) : '');
const canon = (v: unknown): unknown =>
  typeof v === 'string' ? normalize(v) : Array.isArray(v) ? v.map(canon) : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => a.localeCompare(b)).map(([k, x]) => [k, canon(x)])) : v;

// Some corpus fixtures (benign-regressions.json) carry `inputSchema: null` on purpose.
interface Tool { name: string; description?: string; inputSchema?: { properties?: Record<string, unknown> } | null }
const corpus: { file: string; tool: Tool }[] = [];
for (const f of fs.readdirSync(path.join(repo, 'bench/corpus')).filter((f) => f.endsWith('.json'))) {
  const data = JSON.parse(fs.readFileSync(path.join(repo, 'bench/corpus', f), 'utf8')) as unknown;
  if (!Array.isArray(data)) continue;
  for (const it of data) if (it && typeof it === 'object' && 'tool' in it) corpus.push({ file: f, tool: (it as { tool: Tool }).tool });
}
const pairs = new Map<string, string>();
const names = new Map<string, string>();
const descs = new Map<string, string>();
const props = new Map<string, string>();
for (const c of corpus) {
  const where = `${c.file}:${c.tool.name}`;
  pairs.set(`${N(c.tool.name)}\u0000${N(c.tool.description)}`, where);
  names.set(N(c.tool.name), where);
  if (N(c.tool.description)) descs.set(N(c.tool.description), where);
  for (const [k, v] of Object.entries(c.tool.inputSchema?.properties ?? {})) props.set(JSON.stringify([N(k), canon(v)]), where);
}

const cand = JSON.parse(fs.readFileSync(path.join(work, 'candidates.json'), 'utf8')) as { items: { kind: string; source: string; oos_param?: string[]; tool: Tool; overlap?: string }[] };
const kept = [];
const overlaps = [];
for (const it of cand.items) {
  const hits: string[] = [];
  const pair = pairs.get(`${N(it.tool.name)}\u0000${N(it.tool.description)}`);
  if (pair) hits.push(`identical name+description: ${pair}`);
  if (/prompt injection|preference manipulation/.test(it.kind)) {
    const d = descs.get(N(it.tool.description));
    if (d) hits.push(`identical description: ${d}`);
  }
  if (/name collision/.test(it.kind)) {
    const n = names.get(N(it.tool.name));
    if (n) hits.push(`identical name: ${n}`);
  }
  for (const p of it.oos_param ?? []) {
    const hit = props.get(JSON.stringify([N(p), canon(it.tool.inputSchema?.properties?.[p])]));
    if (hit) hits.push(`identical out-of-scope parameter ${p}: ${hit}`);
  }
  if (hits.length) overlaps.push({ source: it.source, name: it.tool.name, kind: it.kind, overlap: hits });
  else kept.push(it);
}
fs.writeFileSync(path.join(work, 'deduped.json'), JSON.stringify({ ...cand, items: kept, overlaps }, null, 1));
process.stdout.write(`corpus definitions compared: ${corpus.length}; candidates ${cand.items.length}; overlaps ${overlaps.length}; kept ${kept.length}\n`);
for (const o of overlaps) process.stdout.write(`  OVERLAP ${o.name} (${o.kind}): ${o.overlap.join('; ')}\n`);
