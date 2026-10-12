import fs from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { ToolListChangedNotificationSchema, type Tool } from '@modelcontextprotocol/sdk/types.js';
import { RugpullChecker, pinsFrom } from '../src/rugpull/checker.js';
import { loadLockfile, lockPathFor, saveLockfile } from '../src/rugpull/lockfile.js';
import { fixtureServer, startGateway, tempDir, type GatewayHarness } from './helpers.js';

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

describe('gateway: rug-pull enforcement at list time', () => {
  it('hides a tool whose definition differs from the pin, and keeps a matching one', async () => {
    // Pin the CLEAN poisoned-fixture persona, then run the POISONED persona against those pins.
    const cleanTools: Tool[] = [
      { name: 'summarize', description: 'Summarize the given text.', inputSchema: { type: 'object', properties: {} } },
      { name: 'ping', description: 'Return pong. A perfectly ordinary health-check tool with no tricks.', inputSchema: { type: 'object', properties: {} } },
    ];
    const pins = pinsFrom({ p: cleanTools }, {}, {});
    const h = await gw({ p: fixtureServer('poisoned') }, { config: { scan: { enabled: false, block: 'medium', mode: 'hide' } }, rugpull: new RugpullChecker(pins, true) });
    const names = (await h.client.listTools()).tools.map((t) => t.name);
    expect(names).toContain('p__ping'); // identical to its pin → allowed
    expect(names).not.toContain('p__summarize'); // description changed vs pin → hidden
    const rp = h.store.events({ kind: 'rugpull' });
    expect(rp.find((e) => e.name === 'p__summarize')?.outcome).toBe('hidden');
    // tools never pinned are 'new' → also hidden under enforce
    expect(names).not.toContain('p__backup');
  });

  it('observe mode keeps changed tools but records them', async () => {
    const pins = pinsFrom({ p: [{ name: 'ping', description: 'old', inputSchema: { type: 'object' } }] }, {}, {});
    const h = await gw({ p: fixtureServer('poisoned', { env: { PERSONA: 'clean' } }) }, { config: { scan: { enabled: false, block: 'medium', mode: 'hide' }, rugpull: { mode: 'observe', on_bad_signature: 'refuse' } }, rugpull: new RugpullChecker(pins, true) });
    const names = (await h.client.listTools()).tools.map((t) => t.name);
    expect(names).toContain('p__ping'); // changed but observe → kept
    expect(h.store.events({ kind: 'rugpull' }).some((e) => e.name === 'p__ping' && e.outcome === 'flagged')).toBe(true);
  });

  it('catches a rug-pull that arrives mid-session via list_changed', async () => {
    const flagDir = tempDir('mcphantom-rp-');
    dirs.push(flagDir);
    const flag = path.join(flagDir, 'pull');
    // Pin the benign weather tool as it is before the pull.
    const pins = pinsFrom({ r: [{ name: 'weather', description: 'Get the weather for a city.', inputSchema: { type: 'object', properties: { city: { type: 'string' } } } }] }, {}, {});
    let changes = 0;
    const h = await gw(
      { r: fixtureServer('rugpull', { env: { RUGPULL_FLAG: flag } }) },
      { config: { scan: { enabled: false, block: 'medium', mode: 'hide' } }, rugpull: new RugpullChecker(pins, true), setupClient: (c) => { c.setNotificationHandler(ToolListChangedNotificationSchema, () => { changes++; }); } },
    );
    expect((await h.client.listTools()).tools.map((t) => t.name)).toEqual(['r__weather']); // matches pin
    fs.writeFileSync(flag, 'go'); // trigger the pull
    await new Promise((r) => setTimeout(r, 500));
    expect(changes).toBeGreaterThanOrEqual(1);
    const names = (await h.client.listTools()).tools.map((t) => t.name);
    expect(names).not.toContain('r__weather'); // description changed → hidden
    expect(names).not.toContain('r__exfil'); // new tool → hidden
    expect(h.store.events({ kind: 'rugpull' }).some((e) => e.outcome === 'hidden')).toBe(true);
  });
});

describe('lockfile round-trip and HMAC', () => {
  function cfgPath(): string {
    const d = tempDir('mcphantom-lock-');
    dirs.push(d);
    fs.writeFileSync(path.join(d, 'cfg.yaml'), 'version: 1\n');
    return path.join(d, 'cfg.yaml');
  }

  it('saves and verifies, and detects tampering', () => {
    const cfg = cfgPath();
    const keyDir = path.dirname(cfg);
    const data = pinsFrom({ a: [{ name: 't', description: 'd', inputSchema: { type: 'object' } }] }, {}, {});
    const p = saveLockfile(cfg, keyDir, data);
    expect(loadLockfile(cfg, keyDir).integrity).toBe('ok');
    expect(lockPathFor(cfg)).toBe(p);
    // Tamper: flip a pinned fingerprint in the file.
    const raw = fs.readFileSync(p, 'utf8').replace(/("t":\s*")[0-9a-f]{4}/, '$1dead');
    fs.writeFileSync(p, raw);
    expect(loadLockfile(cfg, keyDir).integrity).toBe('bad-signature');
  });

  it('reports missing-key when the key is gone', () => {
    const cfg = cfgPath();
    const keyDir = path.dirname(cfg);
    saveLockfile(cfg, keyDir, pinsFrom({ a: [] }, {}, {}));
    fs.rmSync(path.join(keyDir, 'hmac.key'));
    expect(loadLockfile(cfg, keyDir).integrity).toBe('missing-key');
  });

  it('empty when no lockfile exists', () => {
    const cfg = cfgPath();
    expect(loadLockfile(cfg, path.dirname(cfg)).integrity).toBe('empty');
  });
});

describe('gateway: a hostile definition is isolated (fail-closed per item)', () => {
  it('hides a tool whose schema is too deep to canonicalise, keeps the rest', async () => {
    let deep: Record<string, unknown> = { type: 'string' };
    for (let i = 0; i < 400; i++) deep = { type: 'object', properties: { x: deep } };
    const tools: Tool[] = [
      { name: 'ok', description: 'fine', inputSchema: { type: 'object' } },
      { name: 'deep', description: 'nasty', inputSchema: deep as Tool['inputSchema'] },
    ];
    const toolsFile = path.join(tempDir('mcphantom-custom-'), 'tools.json');
    dirs.push(path.dirname(toolsFile));
    fs.writeFileSync(toolsFile, JSON.stringify(tools));
    // Pin matching the shallow tool so the rug-pull path runs canonicalize on the deep one.
    const pins = pinsFrom({ s: [tools[0] as Tool] }, {}, {});
    const h = await startGateway({ s: fixtureServer('custom', { env: { CUSTOM_TOOLS_FILE: toolsFile } }) }, { config: { scan: { enabled: false, block: 'medium', mode: 'hide' } }, rugpull: new RugpullChecker(pins, true) });
    harnesses.push(h);
    const names = (await h.client.listTools()).tools.map((t) => t.name);
    expect(names).toContain('s__ok');
    expect(names).not.toContain('s__deep');
  });
});
