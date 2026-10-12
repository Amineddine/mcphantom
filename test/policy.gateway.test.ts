import fs from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { fixtureServer, startGateway, tempDir, textOf, type GatewayHarness } from './helpers.js';

const harnesses: GatewayHarness[] = [];
const dirs: string[] = [];
async function gw(...a: Parameters<typeof startGateway>): Promise<GatewayHarness> {
  const h = await startGateway(...a);
  harnesses.push(h);
  return h;
}
afterEach(async () => {
  await Promise.all(harnesses.splice(0).map((h) => h.close()));
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});

function customServer(tools: Tool[], extra: Record<string, unknown> = {}): Record<string, unknown> {
  const f = path.join(tempDir('mcphantom-pol-'), 'tools.json');
  dirs.push(path.dirname(f));
  fs.writeFileSync(f, JSON.stringify(tools));
  return { ...fixtureServer('custom', { env: { CUSTOM_TOOLS_FILE: f } }), ...extra };
}

describe('gateway: policy enforcement end to end', () => {
  const sendTool: Tool = { name: 'send', description: 'send a message', inputSchema: { type: 'object', properties: { to: { type: 'string' }, body: { type: 'string' } } } };

  it('denies a call that violates a deny rule, with a tool error naming the policy', async () => {
    const server = customServer([sendTool], { tools: { send: { effect: 'egress', integrity: 'trusted', rules: [{ deny: 'arg.to in ["blocked@evil.example"]' }] } } });
    const h = await gw({ s: server });
    const ok = await h.client.callTool({ name: 's__send', arguments: { to: 'ok@corp.example', body: 'hi' } });
    expect((ok as { isError?: boolean }).isError).toBeFalsy();
    const denied = await h.client.callTool({ name: 's__send', arguments: { to: 'blocked@evil.example', body: 'hi' } });
    expect((denied as { isError?: boolean }).isError).toBe(true);
    expect(textOf(denied)).toContain('MCPhantom blocked');
    expect(h.store.events({ kind: 'decision' }).some((e) => e.outcome === 'denied')).toBe(true);
  });

  // Owner note #1: a renamed argument must fail closed, in observe mode too.
  it('OBSERVE mode: a rule referencing a renamed/absent argument fails closed (deny + log), never silently allows', async () => {
    // The tool now takes `recipient`, but the policy rule still references `to` (renamed upstream).
    const renamed: Tool = { name: 'send', description: 'send', inputSchema: { type: 'object', properties: { recipient: { type: 'string' }, body: { type: 'string' } } } };
    const server = customServer([renamed], { tools: { send: { effect: 'egress', integrity: 'trusted', rules: [{ allow: 'arg.to in ["ok@corp.example"]' }] } } });
    // Even with the trifecta in audit mode, the policy error must still deny.
    const h = await gw({ s: server }, { config: { taint: { trifecta: 'log', max_index_mb: 32 } } });
    const d = await h.client.callTool({ name: 's__send', arguments: { recipient: 'ok@corp.example', body: 'hi' } });
    expect((d as { isError?: boolean }).isError).toBe(true);
    const dec = h.store.events({ kind: 'decision' }).map((e) => JSON.parse(e.payload ?? '{}') as { verdict?: string; policy?: { errors?: { message: string }[] } });
    expect(dec.some((x) => x.verdict === 'deny' && x.policy?.errors?.some((e) => /not in the call: to/.test(e.message)))).toBe(true);
  });

  it('a declassify entry lifts the trifecta for its tool', async () => {
    const CANARY = 'AKIAGWPOLICYCANARY01'.slice(0, 20);
    const servers = {
      web: fixtureServer('everything'),
      s: customServer([sendTool], { tools: { send: { effect: 'egress', integrity: 'trusted' } } }),
    };
    const declassify = [{ id: 'inbox', tool: 's__send', when: 'arg.to in ["me@corp.example"]', reason: 'own inbox' }];
    const h = await gw(servers, { config: { declassify } });
    // Build the trifecta: untrusted (web echo) + secret (web env-like content) in context.
    await h.client.callTool({ name: 'web__echo', arguments: { text: 'untrusted page content' } });
    await h.client.callTool({ name: 'web__echo', arguments: { text: 'AWS_ACCESS_KEY_ID=' + CANARY } });
    const blocked = await h.client.callTool({ name: 's__send', arguments: { to: 'attacker@evil.example', body: 'x' } });
    expect((blocked as { isError?: boolean }).isError).toBe(true);
    const allowed = await h.client.callTool({ name: 's__send', arguments: { to: 'me@corp.example', body: 'x' } });
    expect((allowed as { isError?: boolean }).isError).toBeFalsy();
  });
});
