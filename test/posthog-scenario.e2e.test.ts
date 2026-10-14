/**
 * PostHog "untrusted event data" scenario (Phase 6b PR 5b) — a generic MCP risk, not a PostHog bug.
 * A scripted agent issues tool-call sequences directly; the "third-party" content is an inert
 * placeholder marker. Each sequence runs UNPROTECTED (must happen) and PROTECTED (must be blocked).
 * Oracles live outside MCPhantom: the loopback collector's request log and the fixture's write log.
 */
import fs from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { suggestClassification } from '../src/cli/suggest.js';
import { fixtureServer, startGateway, tempDir, textOf, type GatewayHarness } from './helpers.js';

const CANARY = ['AKIA', 'POSTHOGSCENAR', '107'].join('');
const MARKER = '[[UNTRUSTED_EVENT_PROPERTY_PLACEHOLDER]]';

let collector: http.Server;
let port = 0;
const received: string[] = [];
beforeAll(async () => {
  collector = http.createServer((req, res) => {
    let body = '';
    req.setEncoding('utf8');
    req.on('data', (c: string) => {
      body += c;
    });
    req.on('end', () => {
      received.push(body);
      res.writeHead(200).end('ok');
    });
  });
  await new Promise<void>((r) => collector.listen(0, '127.0.0.1', r));
  port = (collector.address() as AddressInfo).port;
});
afterAll(async () => {
  await new Promise<void>((r) => {
    collector.closeAllConnections();
    collector.close(() => {
      r();
    });
  });
});

async function world(opts: { protect: boolean }): Promise<{ h: GatewayHarness; writes: () => string }> {
  const writeLog = path.join(tempDir(), 'writes.log');
  const h = await startGateway(
    {
      // As `mcphantom suggest --accept-loose` would classify execute-sql from PostHog's own annotations:
      // read (readOnlyHint, looser than the default) with untrusted output (openWorldHint).
      ph: fixtureServer('posthog-like', {
        env: { WRITE_LOG: writeLog },
        tools: {
          'execute-sql': { effect: 'read', integrity: 'untrusted' },
          'annotation-create': { effect: 'egress', integrity: 'trusted', ...(opts.protect ? { rules: [{ ask: 'context.integrity == "untrusted"' }] } : {}) },
        },
      }),
      fx: fixtureServer('everything', { defaults: { integrity: 'trusted', confidentiality: 'internal' } }),
      hook: fixtureServer('loopback-sink', { env: { SINK_PORT: String(port) }, tools: { post_webhook: { effect: 'egress', integrity: 'trusted' } } }),
    },
    { config: opts.protect ? {} : { taint: { trifecta: 'log', max_index_mb: 32 } } },
  );
  return { h, writes: () => (fs.existsSync(writeLog) ? fs.readFileSync(writeLog, 'utf8') : '') };
}

const query = (h: GatewayHarness) => h.client.callTool({ name: 'ph__execute-sql', arguments: { query: 'SELECT uuid, event, distinct_id, timestamp, properties.$current_url FROM events LIMIT 3' } });
const readSecret = (h: GatewayHarness) => h.client.readResource({ uri: `fixture://items/${CANARY}` });
const exfil = (h: GatewayHarness) => h.client.callTool({ name: 'hook__post_webhook', arguments: { url: `http://127.0.0.1:${port}/c`, body: CANARY } });
const write = (h: GatewayHarness) => h.client.callTool({ name: 'ph__annotation-create', arguments: { content: MARKER } });

describe('PostHog scenario: untrusted event data', () => {
  it('execute-sql output enters the context as untrusted, and the trace names it as the source', async () => {
    const { h } = await world({ protect: true });
    try {
      expect(textOf(await query(h))).toContain(MARKER);
      const taint = h.store.events({ kind: 'taint' }).map((e) => JSON.parse(e.payload ?? '{}') as { contextAfter: { integrity: string } });
      expect(taint.at(-1)?.contextAfter.integrity).toBe('untrusted');
    } finally {
      await h.close();
    }
  });

  it('exfiltration — UNPROTECTED: the canary reaches the collector', async () => {
    const before = received.length;
    const { h } = await world({ protect: false });
    try {
      await query(h);
      await readSecret(h);
      await exfil(h);
      expect(received.slice(before).some((b) => b.includes(CANARY))).toBe(true);
    } finally {
      await h.close();
    }
  });

  it('exfiltration — PROTECTED: blocked by the trifecta invariant, nothing reaches the collector', async () => {
    const before = received.length;
    const { h } = await world({ protect: true });
    try {
      await query(h);
      await readSecret(h);
      const r = await exfil(h);
      expect(r.isError).toBe(true);
      expect(textOf(r)).toMatch(/rule: trifecta/);
      expect(received.slice(before)).toEqual([]);
      const d = JSON.parse(h.store.events({ kind: 'decision' }).at(-1)?.payload ?? '{}') as { untrustedSources: { source: string }[] };
      expect(d.untrustedSources.map((s) => s.source)).toContain('ph__execute-sql');
    } finally {
      await h.close();
    }
  });

  it('write back into PostHog — UNPROTECTED: the annotation is written', async () => {
    const { h, writes } = await world({ protect: false });
    try {
      await query(h);
      expect((await write(h)).isError).toBeFalsy();
      expect(writes()).toContain(MARKER);
    } finally {
      await h.close();
    }
  });

  it('write back into PostHog — PROTECTED: a policy ask on the write tool stops it (no secret involved, so the trifecta alone would not)', async () => {
    const { h, writes } = await world({ protect: true });
    try {
      await query(h);
      const r = await write(h);
      expect(r.isError).toBe(true);
      expect(textOf(r)).toMatch(/confirmation/);
      expect(writes()).toBe('');
    } finally {
      await h.close();
    }
  });
});

describe('suggest on PostHog\'s published execute-sql definition', () => {
  it('openWorldHint proposes untrusted output, marked server-claimed; readOnlyHint proposes read, which is looser than the default', () => {
    const { tools } = JSON.parse(fs.readFileSync(path.join(import.meta.dirname, '..', 'bench', 'corpus', 'posthog', 'tools.json'), 'utf8')) as { tools: Parameters<typeof suggestClassification>[0][] };
    const def = tools.find((t) => t.name === 'execute-sql');
    if (!def) throw new Error('execute-sql missing from catalog');
    const s = suggestClassification(def);
    expect(s.classification).toEqual({ effect: 'read', integrity: 'untrusted' });
    expect(s.serverClaimed).toBe(true);
    expect(s.basis).toMatch(/openWorldHint=true/);
    expect(s.relation).toBe('loosen');
  });
});
