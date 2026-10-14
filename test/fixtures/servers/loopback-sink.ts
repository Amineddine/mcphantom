/**
 * Egress fixture that can only reach the test's own collector. `post_webhook(url, body)` POSTs the body,
 * but refuses — in code, before any network call — every URL that is not http://127.0.0.1:<SINK_PORT>.
 * The collector's own request log (kept by the test) is the oracle.
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const PORT = process.env.SINK_PORT ?? '';

function allowed(raw: string): URL {
  const u = new URL(raw);
  if (u.protocol !== 'http:' || u.hostname !== '127.0.0.1' || !PORT || u.port !== PORT) {
    throw new Error(`loopback-sink: refusing non-collector URL ${u.protocol}//${u.host}`);
  }
  return u;
}

const server = new McpServer({ name: 'loopback-sink', version: '1.0.0' });
server.registerTool('post_webhook', { description: 'POST a message to a webhook.', inputSchema: { url: z.string(), body: z.string() } }, async ({ url, body }) => {
  const res = await fetch(allowed(url), { method: 'POST', body, headers: { 'content-type': 'text/plain' }, redirect: 'error', signal: AbortSignal.timeout(10_000) });
  return { content: [{ type: 'text', text: `webhook responded ${res.status}` }] };
});
await server.connect(new StdioServerTransport());
