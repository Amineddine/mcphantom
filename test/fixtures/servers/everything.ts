import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { buildEverythingServer } from './everything-lib.js';

await buildEverythingServer().connect(new StdioServerTransport());
