#!/usr/bin/env node
/**
 * Imports real, licence-checked tool definitions from first-party MCP servers into the scanner's benign
 * corpus (Phase 6b, corpus >= 200). Pinned commits; re-running reproduces the files byte for byte.
 *
 *   node bench/corpus/import-benign-thirdparty.mjs
 *
 * Sources (licences checked 2026-10-14; notices in NOTICE):
 *  - github/github-mcp-server @ c59e8c1 (MIT): the tool-definition snapshots the project itself
 *    tests against (pkg/github/__toolsnaps__/*.snap) — the exact objects its tools/list returns.
 *  - microsoft/playwright-mcp @ b8b4183 (Apache-2.0): the tool reference in README.md, generated from
 *    the tool definitions by the project's update-readme.js. Reconstructed into Tool objects here:
 *    names, titles, descriptions and parameter descriptions are the real model-visible text; the
 *    JSON Schema around them is rebuilt from the documented types, so schema details beyond type,
 *    description and required-ness are not reproduced.
 * Only model-visible fields are kept (name, title, description, input/output schema, annotations).
 * No third-party server code is executed.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const GH = { repo: 'github/github-mcp-server', sha: 'c59e8c199efbf14467211861de44afaeeb6873e3', licence: 'MIT' };
const PW = { repo: 'microsoft/playwright-mcp', sha: 'b8b4183e099f136cbec0388a6088d4aa2f6b9685', licence: 'Apache-2.0' };
const raw = (src, p) => `https://raw.githubusercontent.com/${src.repo}/${src.sha}/${p}`;

async function get(url) {
  const res = await fetch(url, { headers: { 'user-agent': 'mcphantom-corpus-import' } });
  if (!res.ok) throw new Error(`${res.status} ${url}`);
  return res.text();
}

async function github() {
  const listing = JSON.parse(await get(`https://api.github.com/repos/${GH.repo}/contents/pkg/github/__toolsnaps__?ref=${GH.sha}`));
  const out = [];
  for (const f of listing.filter((x) => x.name.endsWith('.snap')).sort((a, b) => a.name.localeCompare(b.name))) {
    const t = JSON.parse(await get(raw(GH, `pkg/github/__toolsnaps__/${f.name}`)));
    const tool = { name: t.name, description: t.description, inputSchema: t.inputSchema };
    if (t.outputSchema) tool.outputSchema = t.outputSchema;
    if (t.annotations) tool.annotations = t.annotations;
    out.push({ source: `${GH.repo}@${GH.sha.slice(0, 7)} (${GH.licence})`, label: 'benign', tool });
  }
  return out;
}

async function playwright() {
  const md = await get(raw(PW, 'README.md'));
  const out = [];
  const seen = new Set();
  const blocks = md.split(/\n(?=- \*\*[a-z_]+\*\*\n)/);
  for (const b of blocks) {
    const head = /^- \*\*([a-z_]+)\*\*\n/.exec(b);
    if (!head) continue;
    const name = head[1];
    if (seen.has(name)) continue;
    const title = /\n {2}- Title: (.+)/.exec(b)?.[1]?.trim();
    const description = /\n {2}- Description: (.+)/.exec(b)?.[1]?.trim();
    if (!description) continue;
    const readOnly = /\n {2}- Read-only: \*\*(true|false)\*\*/.exec(b)?.[1];
    const properties = {};
    const required = [];
    for (const m of b.matchAll(/\n {4}- `([A-Za-z0-9_]+)` \(([a-z]+)(, optional)?\): (.+)/g)) {
      properties[m[1]] = { type: m[2], description: m[4].trim() };
      if (!m[3]) required.push(m[1]);
    }
    const tool = { name, description, inputSchema: { type: 'object', properties, ...(required.length ? { required } : {}) } };
    if (title || readOnly) tool.annotations = { ...(title ? { title } : {}), ...(readOnly ? { readOnlyHint: readOnly === 'true' } : {}) };
    seen.add(name);
    out.push({ source: `${PW.repo}@${PW.sha.slice(0, 7)} README (${PW.licence})`, label: 'benign', tool });
  }
  return out;
}

const here = path.dirname(fileURLToPath(import.meta.url));
const write = (file, items) => {
  fs.writeFileSync(path.join(here, file), JSON.stringify(items, null, 1) + '\n');
  process.stdout.write(`wrote ${file}: ${items.length} tools\n`);
};
write('benign-github.json', await github());
write('benign-playwright.json', await playwright());
