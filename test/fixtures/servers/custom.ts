/**
 * Generic fixture: serves whatever tool definitions are in the JSON file named by CUSTOM_TOOLS_FILE
 * (and, optionally, prompts from CUSTOM_PROMPTS_FILE and server instructions from the text file
 * CUSTOM_INSTRUCTIONS_FILE). Lets a test hand the gateway arbitrary (including hostile) definitions
 * without a bespoke server.
 */
import fs from 'node:fs';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, GetPromptRequestSchema, ListPromptsRequestSchema, ListToolsRequestSchema, type Prompt, type Tool } from '@modelcontextprotocol/sdk/types.js';

const file = process.env.CUSTOM_TOOLS_FILE ?? '';
const tools = file ? (JSON.parse(fs.readFileSync(file, 'utf8')) as Tool[]) : [];
const promptsFile = process.env.CUSTOM_PROMPTS_FILE ?? '';
const prompts = promptsFile ? (JSON.parse(fs.readFileSync(promptsFile, 'utf8')) as Prompt[]) : undefined;
const instructionsFile = process.env.CUSTOM_INSTRUCTIONS_FILE ?? '';
const instructions = instructionsFile ? fs.readFileSync(instructionsFile, 'utf8') : undefined;

// eslint-disable-next-line @typescript-eslint/no-deprecated -- low-level server to serve raw tool defs
const server = new Server(
  { name: 'custom-fixture', version: '1.0.0' },
  { capabilities: { tools: {}, ...(prompts ? { prompts: {} } : {}) }, ...(instructions !== undefined ? { instructions } : {}) },
);
server.setRequestHandler(ListToolsRequestSchema, () => ({ tools }));
if (prompts) {
  server.setRequestHandler(ListPromptsRequestSchema, () => ({ prompts }));
  server.setRequestHandler(GetPromptRequestSchema, (req) => ({ messages: [{ role: 'user', content: { type: 'text', text: `prompt ${req.params.name}` } }] }));
}
server.setRequestHandler(CallToolRequestSchema, (req) => ({ content: [{ type: 'text', text: `called ${req.params.name}` }] }));
await server.connect(new StdioServerTransport());
