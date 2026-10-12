/**
 * Demo MCP server: read-only access to one workspace directory (argv[2]). Paths are resolved with
 * realpath and must stay inside the root, so symlinks and `..` cannot escape it.
 */
import fs from 'node:fs';
import path from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const rootArg = process.argv[2];
if (!rootArg) {
  process.stderr.write('usage: files <workspace-dir>\n');
  process.exit(2);
}
const ROOT = fs.realpathSync(rootArg);

function inside(rel: string): string {
  const target = fs.realpathSync(path.resolve(ROOT, rel));
  const r = path.relative(ROOT, target);
  if (r.startsWith('..') || path.isAbsolute(r)) throw new Error(`path is outside the workspace: ${rel}`);
  return target;
}

const server = new McpServer({ name: 'demo-files', version: '1.0.0' });

server.registerTool(
  'list_files',
  { description: 'List files in a workspace directory.', inputSchema: { dir: z.string().default('.') } },
  ({ dir }) => {
    try {
      const entries = fs.readdirSync(inside(dir), { withFileTypes: true }).map((e) => (e.isDirectory() ? `${e.name}/` : e.name));
      return { content: [{ type: 'text', text: entries.join('\n') }] };
    } catch (err) {
      return { isError: true, content: [{ type: 'text', text: (err as Error).message }] };
    }
  },
);

server.registerTool(
  'read_file',
  { description: 'Read a text file from the workspace.', inputSchema: { path: z.string() } },
  ({ path: p }) => {
    try {
      return { content: [{ type: 'text', text: fs.readFileSync(inside(p), 'utf8').slice(0, 256 * 1024) }] };
    } catch (err) {
      return { isError: true, content: [{ type: 'text', text: (err as Error).message }] };
    }
  },
);

await server.connect(new StdioServerTransport());
