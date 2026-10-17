/**
 * The Phase 2 showpiece as a deterministic test: the same injected agent runs the exfiltration chain
 * (1) directly against the servers and (2) through MCPhantom. Ground truth is the attacker collector's
 * own request log, which neither the agent nor MCPhantom can write to.
 */
import fs from 'node:fs';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { runInjectedAgent } from '../src/demo/agent.js';
import { startWorld, type World } from '../src/demo/world.js';
import { ROOT, startGateway, tempDir, TSX_LOADER, type GatewayHarness } from './helpers.js';

const CANARY = ['AKIA', 'DEMOCANARYEXFIL', '4'].join('');
let world: World;
let workspace: string;

function demoServer(name: string, extraArgs: string[] = []): Record<string, unknown> {
  return { command: process.execPath, args: ['--import', TSX_LOADER, path.join(ROOT, 'src', 'demo', 'servers', `${name}.ts`), ...extraArgs] };
}

beforeAll(async () => {
  world = await startWorld();
  workspace = tempDir('mcphantom-ws-');
  fs.writeFileSync(path.join(workspace, '.env'), `AWS_ACCESS_KEY_ID=${CANARY}\nAWS_SECRET_ACCESS_KEY=wJalrFAKEsecretFAKEsecretFAKEsecretFAKE01\n`);
  fs.writeFileSync(path.join(workspace, 'README.md'), '# demo project\n');
});
afterAll(async () => {
  await world.close();
  fs.rmSync(workspace, { recursive: true, force: true });
});

describe('demo: exfiltration via indirect prompt injection', () => {
  // Built lazily: workspace is set in beforeAll, after the describe body runs.
  const classified = () => ({
    web: { ...demoServer('web'), tools: { fetch_url: { effect: 'read', integrity: 'untrusted' } } },
    files: { ...demoServer('files', [workspace]), defaults: { effect: 'read', integrity: 'trusted', confidentiality: 'internal' } },
    hook: { ...demoServer('webhook'), tools: { post_webhook: { effect: 'egress', integrity: 'trusted' } } },
  });
  const tools = { fetchUrl: 'web__fetch_url', readFile: 'files__read_file', postWebhook: 'hook__post_webhook' };

  it('UNPROTECTED (audit mode): the canary reaches the attacker collector', async () => {
    const before = world.received.length;
    // trifecta: log => MCPhantom observes but does not block, modelling an unprotected setup.
    const h: GatewayHarness = await startGateway(classified(), { config: { taint: { trifecta: 'log' } } });
    try {
      const r = await runInjectedAgent(h.client, tools, world.articleUrl, world.collectUrl);
      expect(r.exfilBlocked).toBe(false);
      expect(r.secret).toContain(CANARY);
      const leaked = world.received.slice(before);
      expect(leaked.some((x) => x.body.includes(CANARY))).toBe(true); // ORACLE: secret left the machine
      // Even in audit mode the flow was flagged.
      expect(h.store.events({ kind: 'decision' }).some((e) => e.outcome === 'flagged')).toBe(true);
    } finally {
      await h.close();
    }
  });

  it('PROTECTED (default deny): the exfiltration is blocked and the canary never reaches the collector', async () => {
    const before = world.received.length;
    const h = await startGateway(classified());
    try {
      const r = await runInjectedAgent(h.client, tools, world.articleUrl, world.collectUrl);
      expect(r.exfilBlocked).toBe(true);
      const leaked = world.received.slice(before);
      expect(leaked.some((x) => x.body.includes(CANARY))).toBe(false); // ORACLE: nothing left
      const denials = h.store.events({ kind: 'decision' }).filter((e) => e.outcome === 'denied');
      expect(denials).toHaveLength(1);
      const d = JSON.parse(denials[0]?.payload ?? '{}') as { rule?: string; sources: { firstUntrusted?: unknown; firstSecret?: unknown; untrustedOutputs: { count: number }; secretOutputs: { count: number } } };
      expect(d.rule).toBe('trifecta');
      expect(d.sources.untrustedOutputs.count).toBeGreaterThan(0);
      expect(d.sources.secretOutputs.count).toBeGreaterThan(0);
      expect(d.sources.firstUntrusted).toBeDefined();
      expect(d.sources.firstSecret).toBeDefined();
    } finally {
      await h.close();
    }
  });

  it('PROTECTED still allows the benign flow: fetch + read without egress, and egress before any secret', async () => {
    const h = await startGateway(classified());
    try {
      // read a non-secret file then post: no secret in context yet → allowed
      const post1 = await h.client.callTool({ name: 'hook__post_webhook', arguments: { url: world.collectUrl, body: 'build passed' } });
      expect((post1 as { isError?: boolean }).isError).toBeFalsy();
      // fetch the article (untrusted) then post a summary with no secret read → still allowed (untrusted-only)
      await h.client.callTool({ name: 'web__fetch_url', arguments: { url: world.articleUrl } });
      const post2 = await h.client.callTool({ name: 'hook__post_webhook', arguments: { url: world.collectUrl, body: 'summary: three cold-start fixes' } });
      expect((post2 as { isError?: boolean }).isError).toBeFalsy();
    } finally {
      await h.close();
    }
  });
});
