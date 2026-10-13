/**
 * Conformance: a client talking to a server through MCPhantom must see the same thing as a client
 * talking to it directly — apart from the documented `<server>__` prefix on tool and prompt names.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { connectDirect, fixtureServer, startGateway, type GatewayHarness } from './helpers.js';

let direct: Client;
let gw: GatewayHarness;

beforeAll(async () => {
  [direct, gw] = await Promise.all([
    connectDirect('everything'),
    // `sole-server` lets an unknown URI reach the upstream, so the JSON-RPC error test below compares
    // the server's own error; the default (deny) refuses it in the gateway (fail-closed.test.ts).
    startGateway({ fx: fixtureServer('everything') }, { config: { resources: { unrouted: 'sole-server' } } }),
  ]);
});

afterAll(async () => {
  await direct.close();
  await gw.close();
});

describe('conformance: direct vs. proxied', () => {
  it('lists the same tools, namespaced, with identical definitions', async () => {
    const d = await direct.listTools();
    const p = await gw.client.listTools();
    const expected = d.tools
      .filter((t) => `fx__${t.name}`.length <= 128) // longer names cannot be namespaced (see gateway.test)
      .map((t) => ({ ...t, name: `fx__${t.name}` }));
    expect(p.tools.map(({ execution: _e, ...t }) => t)).toEqual(expected.map(({ execution: _e, ...t }) => t));
  });

  it.each([
    ['echo', { text: 'hello ünïcödé \u0000 end' }],
    ['add', { a: 2, b: 40 }],
    ['fail', {}],
    ['stats', {}],
  ])('tools/call %s returns an identical result', async (name, args) => {
    const d = await direct.callTool({ name, arguments: args });
    const p = await gw.client.callTool({ name: `fx__${name}`, arguments: args });
    expect(p).toEqual(d);
  });

  it('a tool that throws yields the same error result', async () => {
    const d = await direct.callTool({ name: 'throws', arguments: {} });
    const p = await gw.client.callTool({ name: 'fx__throws', arguments: {} });
    expect(d.isError).toBe(true);
    expect(p).toEqual(d);
  });

  it('propagates JSON-RPC errors with the same code and message', async () => {
    const uri = 'fixture://does-not-exist';
    const d = await direct.readResource({ uri }).then(() => null, (e: unknown) => e);
    const p = await gw.client.readResource({ uri }).then(() => null, (e: unknown) => e);
    expect(d).toHaveProperty('code');
    expect(p).toMatchObject({ code: (d as { code: number }).code, message: (d as Error).message });
  });

  it('resources: list, templates, read (static and templated) are identical', async () => {
    expect(await gw.client.listResources()).toEqual(await direct.listResources());
    expect(await gw.client.listResourceTemplates()).toEqual(await direct.listResourceTemplates());
    for (const uri of ['fixture://readme', 'fixture://items/42']) {
      expect(await gw.client.readResource({ uri })).toEqual(await direct.readResource({ uri }));
    }
  });

  it('prompts: list and get are identical apart from the name prefix', async () => {
    const d = await direct.listPrompts();
    const p = await gw.client.listPrompts();
    expect(p.prompts).toEqual(d.prompts.map((x) => ({ ...x, name: `fx__${x.name}` })));
    expect(await gw.client.getPrompt({ name: 'fx__greet', arguments: { name: 'Ada' } })).toEqual(
      await direct.getPrompt({ name: 'greet', arguments: { name: 'Ada' } }),
    );
  });

  it('completion/complete is identical', async () => {
    const d = await direct.complete({ ref: { type: 'ref/prompt', name: 'greet' }, argument: { name: 'name', value: 'al' } });
    const p = await gw.client.complete({ ref: { type: 'ref/prompt', name: 'fx__greet' }, argument: { name: 'name', value: 'al' } });
    expect(p).toEqual(d);
    expect(p.completion.values).toEqual(['alice', 'albert']);
  });

  it('forwards server instructions, labelled by server', () => {
    expect(gw.client.getInstructions()).toContain("Server 'fx'");
    expect(gw.client.getInstructions()).toContain('Everything fixture: use echo to echo.');
  });
});
