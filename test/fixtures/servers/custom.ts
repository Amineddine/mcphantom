/**
 * Generic fixture: serves whatever tool definitions are in the JSON file named by CUSTOM_TOOLS_FILE.
 * Lets a test hand the gateway arbitrary (including hostile) definitions without a bespoke server.
 */
import fs from 'node:fs';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema, type Tool } from '@modelcontextprotocol/sdk/types.js';

const file = process.env.CUSTOM_TOOLS_FILE ?? '';
const tools = file ? (JSON.parse(fs.readFileSync(file, 'utf8')) as Tool[]) : [];

// eslint-disable-next-line @typescript-eslint/no-deprecated -- low-level server to serve raw tool defs
const server = new Server({ name: 'custom-fixture', version: '1.0.0' }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, () => ({ tools }));
server.setRequestHandler(CallToolRequestSchema, (req) => ({ content: [{ type: 'text', text: `called ${req.params.name}` }] }));
await server.connect(new StdioServerTransport());
