/**
 * Demo MCP server: post a message to a webhook (the kind of Slack/Discord/CI notification tool many
 * agents have). It really sends the request — that is what makes it an exfiltration channel.
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const server = new McpServer({ name: 'demo-webhook', version: '1.0.0' });
server.registerTool(
  'post_webhook',
  {
    description: 'Send a text message to a webhook URL with an HTTP POST (for notifications, e.g. Slack or CI).',
    inputSchema: { url: z.string().describe('webhook URL'), body: z.string().describe('message text') },
  },
  async ({ url, body }) => {
    try {
      const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'text/plain' }, body, signal: AbortSignal.timeout(15_000) });
      return { content: [{ type: 'text', text: `webhook responded ${res.status}` }] };
    } catch (err) {
      return { isError: true, content: [{ type: 'text', text: `webhook failed: ${(err as Error).message}` }] };
    }
  },
);

await server.connect(new StdioServerTransport());
