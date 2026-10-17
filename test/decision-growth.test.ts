/**
 * Regression (Phase 7 item 5, found while building bench:perf): every decision event carried the full lists
 * of the session's untrusted and secret outputs, so redacting and storing it cost ≈ 0.1 ms more per untrusted
 * output seen — 10 ms at 100 outputs, 95 ms at 1,000, ≈ 190 ms at 2,000, on every tools/call — and the lists
 * grew without bound in memory. Now a decision carries a bounded summary that still names the outputs that
 * drove the label, the full list is the session's `taint` events (each output logged once), and the summary's
 * bytes count against the index budget.
 */
import fs from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { afterEach, describe, expect, it } from 'vitest';
import { runTrace } from '../src/cli/trace.js';
import { resolvePaths } from '../src/config/paths.js';
import { ConfigSchema } from '../src/config/schema.js';
import { PolicyEngine } from '../src/policy/engine.js';
import { SqliteStore } from '../src/store/store.js';
import { TaintEngine } from '../src/taint/engine.js';
import { MAX_SOURCE_NAME_CHARS, MAX_SOURCE_NAMES } from '../src/taint/sources.js';
import { silentLogger } from '../src/util/log.js';
import { tempDir } from './helpers.js';

const config = (maxIndexMb = 32) => ConfigSchema.parse({
  version: 1,
  taint: { max_index_mb: maxIndexMb },
  servers: {
    web: { command: 'x', tools: { fetch: { effect: 'read', integrity: 'untrusted' } } },
    vault: { command: 'x', tools: { get: { effect: 'read', integrity: 'trusted', confidentiality: 'secret' } } },
    hook: { command: 'x', tools: { post: { effect: 'egress', integrity: 'trusted' } } },
  },
});
const text = (t: string) => ({ content: [{ type: 'text', text: t }] });

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true }); });
function store(dataDir = path.join(tempDir(), 'data')) {
  dirs.push(path.dirname(dataDir));
  const s = new SqliteStore({ dataDir, payloads: 'redacted', maxPayloadBytes: 65_536, retentionDays: 14, retentionMaxMb: 256, knownSecrets: [], insecurePermissions: 'fix', logger: silentLogger });
  s.startSession({ id: 's' });
  return { s, dataDir };
}

/** A session that read `n` untrusted outputs (from `distinct` different sources) and one secret. */
function session(n: number, distinct = 3, maxIndexMb = 32) {
  const c = config(maxIndexMb);
  const e = new TaintEngine(c, new PolicyEngine(c));
  e.ingest('tool', 'vault', 'vault__get', 'get', text('deploy credential follows'));
  for (let i = 0; i < n; i++) e.ingest(i % 7 === 0 ? 'resource' : 'tool', 'web', `web://page/${String(i % distinct)}/${'p'.repeat(40)}`, 'fetch', text(`page ${String(i)} with ordinary text`));
  return e;
}
const decide = (e: TaintEngine) => e.decide('hook', 'post', 'hook__post', { body: 'weekly summary' });

describe('decision events are bounded in the session length', () => {
  it('a decision is the same size after 100 and after 5,000 untrusted outputs', () => {
    const small = JSON.stringify(decide(session(100))).length;
    const large = JSON.stringify(decide(session(5000))).length;
    expect(large).toBeLessThanOrEqual(small + 64); // ids and counts gain digits; nothing else grows
  });

  it('it still names the outputs that drove the label, not just a count', () => {
    const d = decide(session(500));
    expect(d.verdict).toBe('deny');
    expect(d.rule).toBe('trifecta');
    expect(d.sources.firstSecret?.source).toBe('vault__get');
    expect(d.sources.firstUntrusted?.id).toBe('o2'); // the first untrusted output made the context untrusted
    expect(d.sources.untrustedOutputs.count).toBe(500);
    expect(d.sources.untrustedOutputs.names).toHaveLength(3);
    expect(d.sources.through).toBe('o501');
  });

  it('the in-memory summary stays bounded with thousands of distinct sources, and counts against the index budget', () => {
    const e = session(5000, 5000);
    const d = decide(e);
    expect(d.sources.untrustedOutputs.names).toHaveLength(MAX_SOURCE_NAMES);
    expect(d.sources.untrustedOutputs.others).toBe(5000 - MAX_SOURCE_NAMES);
    const cap = MAX_SOURCE_NAMES * 2 * (2 * MAX_SOURCE_NAME_CHARS + 32) + 3 * (2 * 3 * MAX_SOURCE_NAME_CHARS + 96);
    expect(e.indexStats.externalBytes).toBeGreaterThan(0);
    expect(e.indexStats.externalBytes).toBeLessThanOrEqual(cap);
    // Charged against the same budget: Tier A plus the summary stay within max_index_mb.
    const tiny = session(4000, 4000, 0.0625);
    expect(tiny.indexStats.tierABytes + tiny.indexStats.externalBytes).toBeLessThanOrEqual(0.0625 * 1024 * 1024);
    expect(tiny.indexStats.evicted).toBeGreaterThan(0);
  });

  // The growth probe from the item-5 build, kept as a guard. The ratio is generous (it was ≈ 18× before).
  it('writing a decision event costs about the same after 2,000 untrusted outputs as after 100', () => {
    const cost = (n: number) => {
      const d = decide(session(n));
      const { s } = store();
      const t: number[] = [];
      for (let i = 0; i < 21; i++) {
        const t0 = performance.now();
        s.append({ sessionId: 's', kind: 'decision', payload: d });
        t.push(performance.now() - t0);
      }
      s.close();
      return t.sort((a, b) => a - b)[10] ?? NaN;
    };
    const small = cost(100);
    expect(cost(2000)).toBeLessThan(2 * small + 2);
  });

  it('mcphantom trace rebuilds the full source list from the taint events', () => {
    const e = session(40, 20);
    const { s, dataDir } = store();
    const c = config();
    const replay = new TaintEngine(c, new PolicyEngine(c));
    const log = (r: ReturnType<TaintEngine['ingest']>) => { s.append({ sessionId: 's', kind: 'taint', server: r.ref.server, name: r.ref.source, method: r.ref.kind, payload: { output: r.ref, secretsDetected: r.secretsDetected, contextAfter: r.contextAfter } }); };
    log(replay.ingest('tool', 'vault', 'vault__get', 'get', text('deploy credential follows')));
    for (let i = 0; i < 40; i++) log(replay.ingest(i % 7 === 0 ? 'resource' : 'tool', 'web', `web://page/${String(i % 20)}/${'p'.repeat(40)}`, 'fetch', text(`page ${String(i)} with ordinary text`)));
    s.append({ sessionId: 's', kind: 'decision', server: 'hook', name: 'hook__post', method: 'tools/call', outcome: 'denied', payload: decide(e) });
    s.close();
    const lines: string[] = [];
    expect(runTrace({ dataDir, last: true, json: false, paths: resolvePaths({ MCPHANTOM_HOME: tempDir() }) }, (l) => lines.push(l))).toBe(0);
    const t = lines.join('\n');
    expect(MAX_SOURCE_NAMES).toBeLessThan(20);
    for (let i = 0; i < 20; i++) expect(t).toContain(`web://page/${String(i)}/`);
    expect(t).toContain('40 output(s) — first: web://page/0/');
    expect(t).toContain('secret from:    vault__get; 1 output(s) — first: vault__get (o1)');
  });
});
