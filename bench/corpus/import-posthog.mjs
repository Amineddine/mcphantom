#!/usr/bin/env node
/**
 * Imports PostHog's published MCP tool catalog for the PostHog static scan (Phase 6b PR 5b, owner plan;
 * reported separately from the benign corpus). Pinned commit; re-running reproduces the files.
 *
 *   node bench/corpus/import-posthog.mjs
 *
 * Source: PostHog/posthog @ 61a8655 (MIT outside ee/; notice in NOTICE), services/mcp/schema/:
 *  - tool-definitions-all.json: every tool (1,121) with description, title, annotations and metadata.
 *    Kept: name, title, description, annotations — the fields an MCP Tool carries to the model.
 *  - tool-inputs.json: 43 published input-schema definitions. The mapping from schema name to tool is
 *    in the server's TypeScript, not in these files; only ExecuteSQLSchema -> execute-sql was confirmed
 *    (services/mcp/src/tools/posthogAiTools/executeSql.ts). The other 42 are scanned as schemas, not
 *    attached to tools. The remaining tools' input schemas are generated at build time and are not
 *    published in this directory, so they are NOT covered.
 * Nothing under ee/ (PostHog's enterprise licence) is read or used. No PostHog service is contacted.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SHA = '61a8655e6f7e1b9608f4a69e5486631a5ee2940c';
const base = `https://raw.githubusercontent.com/PostHog/posthog/${SHA}/services/mcp/schema`;
async function json(file) {
  const res = await fetch(`${base}/${file}`, { headers: { 'user-agent': 'mcphantom-corpus-import' } });
  if (!res.ok) throw new Error(`${res.status} ${file}`);
  return res.json();
}

const all = await json('tool-definitions-all.json');
const inputs = (await json('tool-inputs.json')).definitions;
const tools = Object.entries(all)
  .sort(([a], [b]) => a.localeCompare(b))
  .map(([name, d]) => {
    const tool = { name, description: d.description ?? '' };
    if (d.title) tool.title = d.title;
    if (d.annotations) tool.annotations = d.annotations;
    return tool;
  });
const execSql = tools.find((t) => t.name === 'execute-sql');
if (!execSql || !inputs.ExecuteSQLSchema) throw new Error('execute-sql or its schema missing');
execSql.inputSchema = inputs.ExecuteSQLSchema;

const here = path.dirname(fileURLToPath(import.meta.url));
const dir = path.join(here, 'posthog');
fs.mkdirSync(dir, { recursive: true });
const meta = { source: `PostHog/posthog@${SHA.slice(0, 7)} services/mcp/schema (MIT)`, commit: SHA };
fs.writeFileSync(path.join(dir, 'tools.json'), JSON.stringify({ ...meta, tools }, null, 1) + '\n');
fs.writeFileSync(path.join(dir, 'input-schemas.json'), JSON.stringify({ ...meta, schemas: inputs }, null, 1) + '\n');
process.stdout.write(`wrote posthog/tools.json (${tools.length} tools) and posthog/input-schemas.json (${Object.keys(inputs).length} schemas)\n`);
