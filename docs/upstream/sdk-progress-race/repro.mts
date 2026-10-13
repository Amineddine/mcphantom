// Run from a project with @modelcontextprotocol/sdk@1.32.1 installed: `npx tsx repro.mts` (PATCHED=1 applies the fix).
// Minimal reproduction for @modelcontextprotocol/sdk: a progress notification that is delivered in the
// same synchronous batch as its request's response is dropped ("unknown token"). This is what happens
// on stdio when both lines land in one read (ReadBuffer dispatches them back-to-back).
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import type { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js';

class BatchingServerTransport implements Transport {
  onmessage?: (m: JSONRPCMessage) => void;
  onclose?: () => void;
  onerror?: (e: Error) => void;
  async start() {}
  async close() { this.onclose?.(); }
  async send(msg: JSONRPCMessage) {
    const m = msg as { id?: number; method?: string; params?: { _meta?: { progressToken?: number } } };
    const deliver = (x: unknown) => this.onmessage?.(x as JSONRPCMessage);
    if (m.method === 'initialize') {
      deliver({ jsonrpc: '2.0', id: m.id, result: { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 's', version: '1' } } });
    } else if (m.method === 'tools/call') {
      const token = m.params?._meta?.progressToken;
      // Final progress and the response arrive together, as in one stdio read:
      deliver({ jsonrpc: '2.0', method: 'notifications/progress', params: { progressToken: token, progress: 1, total: 1 } });
      deliver({ jsonrpc: '2.0', id: m.id, result: { content: [{ type: 'text', text: 'done' }] } });
    }
  }
}

const client = new Client({ name: 'repro', version: '1' });
const errors: string[] = [];
client.onerror = (e) => errors.push(e.message);
if (process.env.PATCHED) {
  // Candidate fix: handle progress synchronously, before a response in the same batch can delete its handler.
  const p = client as unknown as { _onnotification: (n: { method: string }) => void; _notificationHandlers: Map<string, (n: unknown) => unknown> };
  const orig = p._onnotification.bind(client);
  p._onnotification = (n) => {
    if (n.method === "notifications/progress") {
      try { void p._notificationHandlers.get(n.method)?.(n); } catch (e) { errors.push(String(e)); }
      return;
    }
    orig(n);
  };
}
await client.connect(new BatchingServerTransport());
const seen: number[] = [];
await client.callTool({ name: 'work', arguments: {} }, undefined, { onprogress: (p) => seen.push(p.progress) });
await new Promise((r) => setTimeout(r, 20));
console.log(JSON.stringify({ seen, errors }));
