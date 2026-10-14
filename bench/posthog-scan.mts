/**
 * Static scan of PostHog's published MCP tool catalog (Phase 6b PR 5b, owner plan). Reported
 * separately from the 254-definition benign corpus; an evaluation only — nothing is tuned on it.
 *
 *   npm run bench:posthog
 *
 * Input: bench/corpus/posthog/ (import-posthog.mjs; PostHog/posthog @ 61a8655, MIT). PostHog is a
 * legitimate vendor, so every definition MCPhantom would hide here is a false positive of MCPhantom's,
 * and is listed as such. Coverage is stated exactly in the report.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { scanTool, type Finding } from '../src/scanner/scan.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const dir = path.join(here, 'corpus', 'posthog');
const { source, tools } = JSON.parse(fs.readFileSync(path.join(dir, 'tools.json'), 'utf8')) as { source: string; tools: (Omit<Tool, 'inputSchema'> & { inputSchema?: Tool['inputSchema'] })[] };
const { schemas } = JSON.parse(fs.readFileSync(path.join(dir, 'input-schemas.json'), 'utf8')) as { schemas: Record<string, unknown> };

const empty = { type: 'object' as const, properties: {} };
const withSchema = tools.filter((t) => t.inputSchema).length;
const results = tools.map((t) => ({ name: t.name, r: scanTool({ ...t, inputSchema: t.inputSchema ?? empty }) }));
// The 42 schemas not mapped to a tool: scanned as the input schema of a neutral placeholder tool, so
// only the schema's own text can produce a finding.
const schemaResults = Object.entries(schemas)
  .filter(([name]) => name !== 'ExecuteSQLSchema')
  .map(([name, s]) => ({ name, r: scanTool({ name: 'schema', description: '', inputSchema: s as Tool['inputSchema'] }) }));

const hidden = results.filter((x) => x.r.flagged);
const hiddenSchemas = schemaResults.filter((x) => x.r.flagged);
const lowOnly = results.filter((x) => !x.r.flagged && x.r.findings.length > 0);
const byCategory: Record<string, number> = {};
for (const x of [...results, ...schemaResults]) for (const f of x.r.findings) byCategory[`${f.category} (${f.severity})`] = (byCategory[`${f.category} (${f.severity})`] ?? 0) + 1;
const line = (name: string, f: Finding) => `- \`${name}\` — ${f.category} (${f.severity}) in \`${f.where}\`: ${f.detail}${f.via ? ` [via ${f.via}]` : ''}`;
const pct = (n: number, d: number) => `${((100 * n) / d).toFixed(1)}%`;

const md = [
  '# PostHog MCP tool catalog: static scan (`npm run bench:posthog`)',
  '',
  `Source: ${source}, imported by \`bench/corpus/import-posthog.mjs\`. Scanner settings: defaults (block at medium).`,
  '',
  '## Coverage (exact)',
  '',
  `- **${tools.length} tool definitions**: name, title, description and annotations of every tool in \`tool-definitions-all.json\`.`,
  `- **Input schemas: 43 published definitions** (\`tool-inputs.json\`). Only \`ExecuteSQLSchema\` is attached to its tool (\`execute-sql\`, confirmed from source); the other 42 are scanned as standalone schemas because the published files do not say which tool uses them. Tools with a scanned schema: ${withSchema}.`,
  '- **Not covered:** the input schemas of the other tools (generated at build time, not published there), other catalog metadata fields (summary, prompt hints) whose model visibility was not verified, and anything served at runtime. No PostHog service was contacted; nothing under `ee/` was read.',
  '',
  '## Result',
  '',
  `- Tools MCPhantom would **hide** at default settings: **${hidden.length} of ${tools.length} (${pct(hidden.length, tools.length)})**. Each is a false positive of MCPhantom's (PostHog is the vendor), listed below.`,
  `- Standalone schemas flagged: ${hiddenSchemas.length} of ${schemaResults.length}.`,
  `- Tools with only low-severity findings (recorded, still shown): ${lowOnly.length}.`,
  '',
  '| finding (severity) | count |',
  '|---|---|',
  ...Object.entries(byCategory).sort((a, b) => b[1] - a[1]).map(([k, v]) => `| ${k} | ${v} |`),
  '',
  '## Hidden tools (false positives) — every one',
  '',
  ...(hidden.length ? hidden.flatMap((x) => x.r.findings.filter((f) => f.severity !== 'low').map((f) => line(x.name, f))) : ['None.']),
  '',
  '## Flagged standalone schemas',
  '',
  ...(hiddenSchemas.length ? hiddenSchemas.flatMap((x) => x.r.findings.filter((f) => f.severity !== 'low').map((f) => line(x.name, f))) : ['None.']),
  '',
  '## Low-severity findings (recorded, not hidden)',
  '',
  ...(lowOnly.length ? lowOnly.flatMap((x) => x.r.findings.map((f) => line(x.name, f))) : ['None.']),
  '',
];
fs.mkdirSync(path.join(here, 'results'), { recursive: true });
fs.writeFileSync(path.join(here, 'results', 'posthog-scan.md'), md.join('\n'));
process.stdout.write(`${md.slice(0, 22).join('\n')}\n`);
