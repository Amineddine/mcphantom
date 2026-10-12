/**
 * Regression tests for issues found in the Phase 1 hostile review (docs/reviews/phase-1.md).
 */
import fs from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { runInit, runUninstall, type Io } from '../src/cli/init.js';
import { resolvePaths } from '../src/config/paths.js';
import { MAX_MESSAGE_BYTES, sizeLimitedFetch } from '../src/gateway/upstream.js';
import { checkPrivate, restrictFile } from '../src/security/fileperms.js';
import { fixtureServer, startGateway, startHttpFixture, tempDir, textOf, type GatewayHarness } from './helpers.js';

const harnesses: GatewayHarness[] = [];
const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(harnesses.splice(0).map((h) => h.close()));
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  delete process.env.FIXTURE_SECRET;
});

describe('R1: the gateway does not widen the environment servers receive', () => {
  it('env_inherit defaults to minimal: a secret in the gateway environment is not passed on', async () => {
    process.env.FIXTURE_SECRET = 'parent-process-secret-value';
    const h = await startGateway({ fx: fixtureServer('everything') });
    harnesses.push(h);
    expect(textOf(await h.client.callTool({ name: 'fx__env', arguments: {} }))).toBe('secret=(unset)');
  });

  it('env_inherit: all passes it on (explicit opt-in)', async () => {
    process.env.FIXTURE_SECRET = 'parent-process-secret-value';
    const h = await startGateway({ fx: fixtureServer('everything', { env_inherit: 'all' }) });
    harnesses.push(h);
    expect(textOf(await h.client.callTool({ name: 'fx__env', arguments: {} }))).toBe('secret=parent-process-secret-value');
  });
});

describe('R2: resource shadowing fails closed', () => {
  it('a URI listed by two servers is hidden and reads of it are refused, not routed to either', async () => {
    const h = await startGateway({ a: fixtureServer('everything'), b: fixtureServer('everything') });
    harnesses.push(h);
    const listed = (await h.client.listResources()).resources.map((r) => r.uri);
    expect(listed).not.toContain('fixture://readme');
    await expect(h.client.readResource({ uri: 'fixture://readme' })).rejects.toThrow(/several servers/);
    await expect(h.client.readResource({ uri: 'fixture://items/1' })).rejects.toThrow(/several servers/);
    expect(h.store.events({ kind: 'warning' }).some((e) => e.name === 'fixture://readme')).toBe(true);
  });
});

describe('R3: bounded buffering of HTTP upstream responses', () => {
  const body = (chunks: string[], type: string, length?: number) => () => {
    const enc = new TextEncoder();
    const stream = new ReadableStream<Uint8Array>({
      start(c) {
        for (const ch of chunks) c.enqueue(enc.encode(ch));
        c.close();
      },
    });
    const headers: Record<string, string> = { 'content-type': type };
    if (length !== undefined) headers['content-length'] = String(length);
    return Promise.resolve(new Response(stream, { headers }));
  };

  it('rejects an oversized JSON body (declared or streamed)', async () => {
    await expect(sizeLimitedFetch(100, body(['x'], 'application/json', 1000))('http://x')).rejects.toThrow(/exceeds/);
    const res = await sizeLimitedFetch(100, body(['x'.repeat(60), 'y'.repeat(60)], 'application/json'))('http://x');
    await expect(res.text()).rejects.toThrow(/exceeds/);
  });

  it('caps SSE per event, so a long-lived stream of small events keeps working', async () => {
    const events = Array.from({ length: 50 }, (_, i) => `data: ${'e'.repeat(40)}${i}\n\n`);
    const ok = await sizeLimitedFetch(100, body(events, 'text/event-stream'))('http://x');
    expect((await ok.text()).length).toBeGreaterThan(2000);
    const big = await sizeLimitedFetch(100, body([`data: ${'z'.repeat(200)}\n\n`], 'text/event-stream'))('http://x');
    await expect(big.text()).rejects.toThrow(/event exceeds/);
  });

  it('end to end: a tool result over the limit fails the call instead of exhausting memory', async () => {
    const http = await startHttpFixture();
    try {
      const h = await startGateway({ web: { type: 'http', url: http.url } });
      harnesses.push(h);
      await expect(h.client.callTool({ name: 'web__echo', arguments: { text: 'x'.repeat(MAX_MESSAGE_BYTES + 1) } })).rejects.toThrow();
      expect(textOf(await h.client.callTool({ name: 'web__echo', arguments: { text: 'small' } }))).toBe('small');
    } finally {
      await http.close();
    }
  });
});

describe('R4/R5: client config rewrite keeps permissions; uninstall only removes its own entry', () => {
  const quiet: Io = { out: () => {}, confirm: () => Promise.resolve(true) };
  const GW = { command: '/n', args: ['/x/mcphantom/main.js'] };

  function setup() {
    const root = tempDir();
    dirs.push(root);
    const paths = resolvePaths({ MCPHANTOM_HOME: path.join(root, 'home') });
    const file = path.join(root, 'client.json');
    fs.writeFileSync(file, JSON.stringify({ mcpServers: { fs: { command: 'npx', args: ['fs'] } } }, null, 2));
    return { paths, file };
  }

  it('a client config restricted to the owner stays restricted after init', async () => {
    const { paths, file } = setup();
    restrictFile(file);
    expect(checkPrivate(file).ok).toBe(true);
    await runInit({ file, profile: 'p', yes: true, dryRun: false, cwd: '.', paths, gatewayCommand: GW }, quiet);
    expect(checkPrivate(file).ok).toBe(true);
  });

  it('uninstall does not remove a gateway entry that belongs to a different profile', async () => {
    const { paths, file } = setup();
    await runInit({ file, profile: 'p', yes: true, dryRun: false, cwd: '.', paths, gatewayCommand: GW }, quiet);
    const cfg = JSON.parse(fs.readFileSync(file, 'utf8')) as { mcpServers: Record<string, { args: string[] }> };
    const entry = cfg.mcpServers.mcphantom;
    if (!entry) throw new Error('gateway entry missing');
    entry.args = entry.args.map((a) => (a === 'p' ? 'p-other' : a));
    fs.writeFileSync(file, JSON.stringify(cfg, null, 2));
    await runUninstall({ profile: 'p', yes: true, dryRun: false, paths }, quiet);
    const after = JSON.parse(fs.readFileSync(file, 'utf8')) as { mcpServers: Record<string, unknown> };
    expect(after.mcpServers.mcphantom).toBeDefined();
    expect(after.mcpServers.fs).toEqual({ command: 'npx', args: ['fs'] });
  });
});
