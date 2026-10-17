/**
 * The timing hook (Phase 7 item 5) exists for `bench:perf` only. These tests pin that no configuration can
 * reach it, that nothing in the product passes a sink, and that with a sink one `tools/call` reports every
 * gateway stage in order (and the store splits redaction from the SQLite write).
 */
import fs from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { ConfigSchema } from '../src/config/schema.js';
import { SqliteStore } from '../src/store/store.js';
import type { TimingStage } from '../src/util/timings.js';
import { silentLogger } from '../src/util/log.js';
import { fixtureServer, startGateway, tempDir, textOf, type GatewayHarness } from './helpers.js';

describe('the timing hook is not reachable from the configuration', () => {
  for (const key of ['timings', 'timing']) {
    it(`"${key}" is rejected at the top level and in every section`, () => {
      expect(ConfigSchema.safeParse({ version: 1, servers: {}, [key]: true }).success).toBe(false);
      for (const section of ['logging', 'taint', 'retention', 'security']) {
        expect(ConfigSchema.safeParse({ version: 1, servers: {}, [section]: { [key]: true } }).success).toBe(false);
      }
      expect(ConfigSchema.safeParse({ version: 1, servers: { a: { command: 'x', [key]: true } } }).success).toBe(false);
    });
  }
  it('only the gateway, the store and the hook module mention it in src/', () => {
    const src = path.join(import.meta.dirname, '..', 'src');
    const hits: string[] = [];
    const walk = (d: string): void => {
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        const p = path.join(d, e.name);
        if (e.isDirectory()) walk(p);
        else if (p.endsWith('.ts') && /\btimings\b|StageClock|TimingSink/.test(fs.readFileSync(p, 'utf8'))) hits.push(path.relative(src, p).replaceAll('\\', '/'));
      }
    };
    walk(src);
    expect(hits.sort()).toEqual(['gateway/gateway.ts', 'store/store.ts', 'util/timings.ts']);
  });
});

describe('with a sink', () => {
  let h: GatewayHarness | undefined;
  afterEach(async () => {
    await h?.close();
    h = undefined;
  });

  it('one tools/call reports every gateway stage, in order, inside the handler', async () => {
    const marks: [TimingStage, number, number][] = [];
    h = await startGateway({ fx: fixtureServer('everything') }, { timings: (s, a, b) => marks.push([s, a, b]) });
    await h.client.listTools();
    marks.length = 0;
    expect(textOf(await h.client.callTool({ name: 'fx__echo', arguments: { text: 'timed' } }))).toBe('timed');
    const gw = marks.filter(([s]) => s !== 'redact' && s !== 'store.write').map(([s]) => s);
    expect(gw).toEqual(['resolve', 'decide', 'audit.decision', 'sent', 'upstream', 'ingest', 'audit.ingest', 'audit.request', 'handler']);
    const [, start, end] = marks.find(([s]) => s === 'handler') ?? [];
    for (const [, a, b] of marks) {
      expect(b).toBeGreaterThanOrEqual(a);
      expect(a).toBeGreaterThanOrEqual(start ?? Infinity);
      expect(b).toBeLessThanOrEqual(end ?? -Infinity);
    }
  });

  it('a gateway built without one reports nothing and behaves the same', async () => {
    h = await startGateway({ fx: fixtureServer('everything') });
    expect(textOf(await h.client.callTool({ name: 'fx__echo', arguments: { text: 'untimed' } }))).toBe('untimed');
  });

  it('the store reports redaction and the SQLite write for each event', () => {
    const dataDir = tempDir();
    const marks: TimingStage[] = [];
    const store = new SqliteStore({ dataDir, payloads: 'redacted', maxPayloadBytes: 65_536, retentionDays: 14, retentionMaxMb: 256, knownSecrets: [], insecurePermissions: 'fix', logger: silentLogger, timings: (s) => marks.push(s) });
    try {
      store.startSession({ id: 's' });
      store.append({ sessionId: 's', kind: 'request', payload: { a: 1 } });
      expect(marks).toEqual(['redact', 'store.write']);
    } finally {
      store.close();
      fs.rmSync(dataDir, { recursive: true, force: true });
    }
  });
});
