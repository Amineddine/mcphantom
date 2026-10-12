import { afterEach, describe, expect, it } from 'vitest';
import { fixtureServer, startGateway, type GatewayHarness } from './helpers.js';

const harnesses: GatewayHarness[] = [];
async function gw(...a: Parameters<typeof startGateway>): Promise<GatewayHarness> {
  const h = await startGateway(...a);
  harnesses.push(h);
  return h;
}
afterEach(async () => { await Promise.all(harnesses.splice(0).map((h) => h.close())); });

describe('gateway: list-time scanning', () => {
  it('hides poisoned tools and keeps the benign ones', async () => {
    const h = await gw({ p: fixtureServer('poisoned') });
    const names = (await h.client.listTools()).tools.map((t) => t.name);
    // benign tools survive
    expect(names).toContain('p__ping');
    // every poisoned tool is hidden
    for (const bad of ['summarize', 'translate', 'format', 'calc', 'lookup', 'helper', 'backup']) {
      expect(names, `${bad} should be hidden`).not.toContain(`p__${bad}`);
    }
    const scans = h.store.events({ kind: 'scan' });
    expect(scans.filter((e) => e.outcome === 'hidden').length).toBe(7);
    // a hidden tool cannot be called either (route was never registered)
    await expect(h.client.callTool({ name: 'p__backup', arguments: {} })).rejects.toMatchObject({ code: -32602 });
  });

  it('does not hide tools of the clean persona (no false positives on benign variants)', async () => {
    const h = await gw({ p: fixtureServer('poisoned', { env: { PERSONA: 'clean' } }) });
    const names = (await h.client.listTools()).tools.map((t) => t.name);
    expect(names.sort()).toEqual(['p__backup', 'p__calc', 'p__format', 'p__helper', 'p__lookup', 'p__ping', 'p__summarize', 'p__translate']);
    expect(h.store.events({ kind: 'scan' }).filter((e) => e.outcome === 'hidden')).toHaveLength(0);
  });

  it('warn mode keeps flagged tools but still records findings', async () => {
    const h = await gw({ p: fixtureServer('poisoned') }, { config: { scan: { enabled: true, block: 'medium', mode: 'warn' } } });
    const names = (await h.client.listTools()).tools.map((t) => t.name);
    expect(names).toContain('p__backup');
    expect(h.store.events({ kind: 'scan' }).some((e) => e.outcome === 'flagged')).toBe(true);
    expect(h.store.events({ kind: 'scan' }).filter((e) => e.outcome === 'hidden')).toHaveLength(0);
  });

  it('disabled scanning passes everything through', async () => {
    const h = await gw({ p: fixtureServer('poisoned') }, { config: { scan: { enabled: false, block: 'medium', mode: 'hide' } } });
    expect((await h.client.listTools()).tools.map((t) => t.name)).toContain('p__backup');
    expect(h.store.events({ kind: 'scan' })).toHaveLength(0);
  });
});
