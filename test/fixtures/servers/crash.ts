/** Fixture whose `die` tool kills the process mid-call. */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

const server = new McpServer({ name: 'fixture-crash', version: '1.0.0' });
server.registerTool('die', { description: 'Exits the process' }, () => {
  process.exit(3);
});
server.registerTool('alive', { description: 'Still here' }, () => ({ content: [{ type: 'text', text: 'alive' }] }));
await server.connect(new StdioServerTransport());
