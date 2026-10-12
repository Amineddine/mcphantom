/**
 * Low-level server that splits tools/list over three pages. PAGINATE_MODE=cycle makes it return
 * the same cursor forever (the gateway must detect the cycle instead of looping).
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema, type Tool } from '@modelcontextprotocol/sdk/types.js';

const pages: Tool[][] = [1, 2, 3].map((p) =>
  [1, 2, 3].map((i) => ({ name: `t${(p - 1) * 3 + i}`, description: `tool on page ${p}`, inputSchema: { type: 'object' as const } })),
);
const cycle = process.env.PAGINATE_MODE === 'cycle';

// eslint-disable-next-line @typescript-eslint/no-deprecated -- low-level server needed to control cursors
const server = new Server({ name: 'fixture-paginated', version: '1.0.0' }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, (req) => {
  const cursor = req.params?.cursor;
  if (cycle) return { tools: pages[0] ?? [], nextCursor: 'again' };
  const idx = cursor === undefined ? 0 : Number(cursor.slice(1));
  return { tools: pages[idx] ?? [], ...(idx < 2 ? { nextCursor: `p${idx + 1}` } : {}) };
});
server.setRequestHandler(CallToolRequestSchema, (req) => ({ content: [{ type: 'text', text: `called ${req.params.name}` }] }));
await server.connect(new StdioServerTransport());
