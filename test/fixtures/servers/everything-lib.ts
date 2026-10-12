/**
 * Benign fixture server exercising every MCP feature the gateway relays. Used for conformance tests
 * (direct vs. proxied must be indistinguishable apart from tool/prompt namespacing).
 */
import { McpServer, ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js';
import { completable } from '@modelcontextprotocol/sdk/server/completable.js';
import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';

const stats = { cancelled: 0 };

export function buildEverythingServer(): McpServer {
  const server = new McpServer(
    { name: 'fixture-everything', version: '1.0.0' },
    { instructions: 'Everything fixture: use echo to echo.', capabilities: { logging: {}, resources: { subscribe: true } } },
  );

  server.registerTool('echo', { description: 'Echo text back', inputSchema: { text: z.string() } }, ({ text }) => ({
    content: [{ type: 'text', text }],
  }));

  server.registerTool(
    'add',
    {
      description: 'Add two numbers',
      inputSchema: { a: z.number(), b: z.number() },
      outputSchema: { sum: z.number() },
      annotations: { readOnlyHint: true },
    },
    ({ a, b }) => ({ content: [{ type: 'text', text: String(a + b) }], structuredContent: { sum: a + b } }),
  );

  server.registerTool('slow', { description: 'Reports progress', inputSchema: { steps: z.number().int(), delayMs: z.number().int().default(20) } }, async ({ steps, delayMs }, extra) => {
    const token = extra._meta?.progressToken;
    for (let i = 1; i <= steps; i++) {
      if (extra.signal.aborted) {
        stats.cancelled++;
        throw new McpError(ErrorCode.InternalError, 'cancelled');
      }
      await new Promise((r) => setTimeout(r, delayMs));
      if (token !== undefined) {
        await extra.sendNotification({ method: 'notifications/progress', params: { progressToken: token, progress: i, total: steps, message: `step ${i}` } });
      }
    }
    if (extra.signal.aborted) stats.cancelled++;
    return { content: [{ type: 'text', text: `done ${steps}` }] };
  });

  server.registerTool('stats', { description: 'Fixture counters' }, () => ({ content: [{ type: 'text', text: JSON.stringify(stats) }] }));

  server.registerTool('fail', { description: 'Returns a tool error' }, () => ({ content: [{ type: 'text', text: 'it failed' }], isError: true }));

  server.registerTool('throws', { description: 'Throws a protocol error' }, () => {
    throw new McpError(ErrorCode.InvalidParams, 'bad things');
  });

  server.registerTool('env', { description: 'Reads FIXTURE_SECRET', inputSchema: {} }, () => ({
    content: [{ type: 'text', text: `secret=${process.env.FIXTURE_SECRET ?? '(unset)'}` }],
  }));

  server.registerTool('sample', { description: 'Asks the client LLM', inputSchema: { prompt: z.string() } }, async ({ prompt }) => {
    try {
      const r = await server.server.createMessage({ messages: [{ role: 'user', content: { type: 'text', text: prompt } }], maxTokens: 10 });
      return { content: [{ type: 'text', text: `sampled: ${r.content.type === 'text' ? r.content.text : r.content.type}` }] };
    } catch (err) {
      return { content: [{ type: 'text', text: `sampling failed: ${(err as Error).message}` }], isError: true };
    }
  });

  server.registerTool('ask', { description: 'Elicits input' }, async () => {
    const r = await server.server.elicitInput({ message: 'Name?', requestedSchema: { type: 'object', properties: { name: { type: 'string' } }, required: ['name'] } });
    return { content: [{ type: 'text', text: `elicited: ${r.action} ${JSON.stringify(r.content ?? {})}` }] };
  });

  server.registerTool('roots', { description: 'Lists client roots' }, async () => {
    const r = await server.server.listRoots();
    return { content: [{ type: 'text', text: JSON.stringify(r.roots) }] };
  });

  server.registerTool('log', { description: 'Emits a log message', inputSchema: { level: z.enum(['debug', 'info', 'warning', 'error']) } }, async ({ level }) => {
    await server.server.sendLoggingMessage({ level, logger: 'fixture', data: `hello at ${level}` });
    return { content: [{ type: 'text', text: 'logged' }] };
  });

  server.registerTool('x'.repeat(126), { description: 'Name too long to namespace' }, () => ({ content: [{ type: 'text', text: 'long' }] }));

  server.registerResource('readme', 'fixture://readme', { mimeType: 'text/plain', description: 'Static readme' }, (uri) => ({
    contents: [{ uri: uri.href, text: 'fixture readme' }],
  }));

  server.registerResource(
    'item',
    new ResourceTemplate('fixture://items/{id}', { list: undefined }),
    { mimeType: 'application/json' },
    (uri, { id }) => ({ contents: [{ uri: uri.href, text: JSON.stringify({ id }) }] }),
  );

  server.registerPrompt(
    'greet',
    { description: 'Greets someone', argsSchema: { name: completable(z.string(), (v) => ['alice', 'albert', 'bob'].filter((n) => n.startsWith(v))) } },
    ({ name }) => ({ messages: [{ role: 'user', content: { type: 'text', text: `Hello, ${name}!` } }] }),
  );

  return server;
}
