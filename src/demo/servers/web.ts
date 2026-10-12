/**
 * Demo MCP server: fetch a web page as text. Deliberately ordinary — the attack is in the *content*
 * it returns, not in the server (indirect prompt injection).
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { htmlToText } from '../html.js';

const MAX_BYTES = 512 * 1024;

const server = new McpServer({ name: 'demo-web', version: '1.0.0' });
server.registerTool(
  'fetch_url',
  {
    description: 'Fetch a web page over HTTP(S) and return its text content.',
    inputSchema: { url: z.string().describe('http(s) URL to fetch') },
  },
  async ({ url }) => {
    let u: URL;
    try {
      u = new URL(url);
    } catch {
      return { isError: true, content: [{ type: 'text', text: `invalid URL: ${url}` }] };
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return { isError: true, content: [{ type: 'text', text: 'only http(s) URLs are supported' }] };
    try {
      const res = await fetch(u, { redirect: 'follow', signal: AbortSignal.timeout(15_000) });
      const body = (await res.text()).slice(0, MAX_BYTES);
      const type = res.headers.get('content-type') ?? '';
      const text = type.includes('html') ? htmlToText(body) : body;
      return { content: [{ type: 'text', text: `${res.status} ${u.href}\n\n${text}` }] };
    } catch (err) {
      return { isError: true, content: [{ type: 'text', text: `fetch failed: ${(err as Error).message}` }] };
    }
  },
);

await server.connect(new StdioServerTransport());
