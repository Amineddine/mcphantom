/**
 * Layer-2 `cumulative` matcher: an identifier split across fields of one call, or across calls to the
 * same tool, is attributed on the call that completes it.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { ConfigSchema } from '../src/config/schema.js';
import { MAX_SINKS, SINK_WINDOW_MS, SinkBuffers } from '../src/taint/cumulative.js';
import { TaintEngine } from '../src/taint/engine.js';
import { ProvenanceIndex, type OutputRef } from '../src/taint/provenance.js';
import { ElicitRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { fixtureServer, startGateway, startHttpFixture, type GatewayHarness } from './helpers.js';

// Canary in AWS access-key format, assembled at runtime so scanners do not flag the repo.
const CANARY = ['AKIA', 'CUMULATIVE', 'TEST42'].join('');
const ref = (id: string): OutputRef => ({ id, seq: 1, server: 'files', source: 'files__read', kind: 'tool', label: { integrity: 'trusted', confidentiality: 'secret' } });

function indexWithSecret(): ProvenanceIndex {
  const idx = new ProvenanceIndex({ maxTierABytes: 1e6 });
  idx.add(ref('o1'), [`AWS_ACCESS_KEY_ID=${CANARY}\n`]);
  return idx;
}
const T0 = 1_000_000;

describe('cumulative matcher (ProvenanceIndex)', () => {
  it('a secret split across two calls to the same tool is attributed on the completing call', () => {
    const idx = indexWithSecret();
    const first = { body: CANARY.slice(0, 9) };
    expect(idx.attributeCall(first, { sink: 'hook__post', now: T0 }).evidence).toEqual([]);
    idx.recordSent('hook__post', first, T0);
    const second = { body: CANARY.slice(9) };
    expect(idx.attributeCall(second, { sink: 'hook__post', now: T0 + 1000 }).evidence).toEqual([
      expect.objectContaining({ kind: 'identifier:secret', matcher: 'cumulative', priorCalls: 1, output: expect.objectContaining({ id: 'o1' }) }),
    ]);
  });

  it('a secret split across two fields of one call is attributed (was a pinned gap)', () => {
    const idx = indexWithSecret();
    expect(idx.attributeCall({ a: CANARY.slice(0, 10), b: CANARY.slice(10) }, { sink: 'hook__post', now: T0 }).evidence).toEqual([
      expect.objectContaining({ matcher: 'cumulative', priorCalls: 0 }),
    ]);
  });

  it('base64 of a secret sent in three chunks is decoded after reassembly', () => {
    const idx = indexWithSecret();
    const b64 = Buffer.from(`key=${CANARY}`).toString('base64');
    const chunks = [b64.slice(0, 10), b64.slice(10, 22), b64.slice(22)];
    idx.recordSent('hook__post', { data: chunks[0] }, T0);
    idx.recordSent('hook__post', { data: chunks[1] }, T0 + 1);
    expect(idx.attributeCall({ data: chunks[2] }, { sink: 'hook__post', now: T0 + 2 }).evidence[0]).toMatchObject({ matcher: 'cumulative', priorCalls: 2, chain: ['base64'] });
  });

  it('does not repeat evidence a single leaf already produced', () => {
    const idx = indexWithSecret();
    idx.recordSent('hook__post', { body: 'hello ' }, T0);
    const ev = idx.attributeCall({ body: CANARY }, { sink: 'hook__post', now: T0 + 1 }).evidence;
    expect(ev.length).toBeGreaterThan(0);
    expect(ev.every((e) => e.matcher === 'exact')).toBe(true);
  });

  it('only calls recorded as sent count: an attributed-but-not-sent call leaves no piece behind', () => {
    const idx = indexWithSecret();
    idx.attributeCall({ body: CANARY.slice(0, 9) }, { sink: 'hook__post', now: T0 }); // e.g. denied
    expect(idx.attributeCall({ body: CANARY.slice(9) }, { sink: 'hook__post', now: T0 + 1 }).evidence).toEqual([]);
  });

  // 6a review, untested path 6: the exact window boundary (inclusive).
  it('a piece exactly at the window edge is still joined', () => {
    const idx = indexWithSecret();
    idx.recordSent('hook__post', { body: CANARY.slice(0, 9) }, T0);
    expect(idx.attributeCall({ body: CANARY.slice(9) }, { sink: 'hook__post', now: T0 + SINK_WINDOW_MS }).evidence[0]).toMatchObject({ matcher: 'cumulative' });
  });

  it('pieces older than the window are not joined', () => {
    const idx = indexWithSecret();
    idx.recordSent('hook__post', { body: CANARY.slice(0, 9) }, T0);
    expect(idx.attributeCall({ body: CANARY.slice(9) }, { sink: 'hook__post', now: T0 + SINK_WINDOW_MS + 1 }).evidence).toEqual([]);
  });

  // Published bypasses, pinned so they are not silently claimed fixed. Layer 1 still applies.
  it('KNOWN BYPASS: pieces sent to different tools are not reassembled', () => {
    const idx = indexWithSecret();
    idx.recordSent('hook__post', { body: CANARY.slice(0, 9) }, T0);
    expect(idx.attributeCall({ body: CANARY.slice(9) }, { sink: 'mail__send', now: T0 + 1 }).evidence).toEqual([]);
  });

  it('KNOWN BYPASS: pieces sent out of order are not reassembled', () => {
    const idx = indexWithSecret();
    idx.recordSent('hook__post', { body: CANARY.slice(9) }, T0);
    expect(idx.attributeCall({ body: CANARY.slice(0, 9) }, { sink: 'hook__post', now: T0 + 1 }).evidence).toEqual([]);
  });
});

describe('SinkBuffers bounds', () => {
  it('trims per sink and reports it, so decisions are marked degraded', () => {
    const idx = indexWithSecret();
    idx.recordSent('hook__post', { body: 'x'.repeat(20_000) }, T0);
    expect(idx.attributeCall({ body: 'y' }, { sink: 'hook__post', now: T0 + 1 }).degraded).toBe(true);
    expect(idx.attributeCall({ body: 'y' }, { sink: 'other__tool', now: T0 + 1 }).degraded).toBe(false);
  });

  it('drops the least recently used sink beyond the sink cap', () => {
    const b = new SinkBuffers();
    for (let i = 0; i <= MAX_SINKS; i++) b.record(`s${i}`, 'piece', T0);
    expect(b.stats.sinks).toBe(MAX_SINKS);
    expect(b.prior('s0', T0)).toMatchObject({ calls: 0, trimmed: true });
    expect(b.prior(`s${MAX_SINKS}`, T0).calls).toBe(1);
  });

  // 6a review, untested path 6: sink eviction changing a real decision. The lost piece costs the
  // attribution, and the decision says so (degraded) instead of reporting a clean "no evidence".
  it('a sink dropped by the LRU cap loses its piece, and the completing call is marked degraded', () => {
    const idx = indexWithSecret();
    idx.recordSent('hook__post', { body: CANARY.slice(0, 9) }, T0);
    for (let i = 0; i < MAX_SINKS; i++) idx.recordSent(`other__t${i}`, { body: 'unrelated' }, T0 + 1);
    const r = idx.attributeCall({ body: CANARY.slice(9) }, { sink: 'hook__post', now: T0 + 2 });
    expect(r.evidence.filter((e) => e.matcher === 'cumulative')).toEqual([]);
    expect(r.degraded).toBe(true);
  });
});

describe('cumulative matcher through the gateway', () => {
  const harnesses: GatewayHarness[] = [];
  afterEach(async () => {
    await Promise.all(harnesses.splice(0).map((h) => h.close()));
  });

  it('records forwarded calls and attributes the completing piece in the decision trace', async () => {
    // fx__echo is unclassified, so its output is untrusted and the call itself counts as egress.
    // trifecta: log keeps every call flowing so the pieces are actually sent.
    const h = await startGateway({ fx: fixtureServer('everything') }, { config: { taint: { trifecta: 'log', max_index_mb: 32 } } });
    harnesses.push(h);
    // The secret enters the context through a resource read, not through anything sent to fx__echo.
    await h.client.readResource({ uri: `fixture://items/${CANARY}` });
    await h.client.callTool({ name: 'fx__echo', arguments: { text: CANARY.slice(0, 9) } });
    await h.client.callTool({ name: 'fx__echo', arguments: { text: CANARY.slice(9) } });
    const decisions = h.store.events({ kind: 'decision' }).map((e) => JSON.parse(e.payload ?? '{}') as { evidence: { matcher: string; priorCalls?: number }[] });
    const last = decisions[decisions.length - 1];
    expect(last?.evidence.some((e) => e.matcher === 'cumulative' && e.priorCalls === 1)).toBe(true);
  });

  const lastEvidence = (h: GatewayHarness) => {
    const decisions = h.store.events({ kind: 'decision' }).map((e) => JSON.parse(e.payload ?? '{}') as { evidence?: { matcher: string; priorCalls?: number }[] }).filter((d) => d.evidence);
    return decisions[decisions.length - 1]?.evidence ?? [];
  };

  // 6a review, untested path 6: an `ask` that the user approves is forwarded, so it must count as sent;
  // a refused one sent nothing and must not.
  for (const approve of [true, false]) {
    it(`an ask-${approve ? 'approved' : 'refused'} piece ${approve ? 'is' : 'is not'} recorded as sent`, async () => {
      let asks = 0;
      const h = await startGateway(
        { fx: fixtureServer('everything', { tools: { echo: { rules: [{ ask: 'arg.text.size() < 10' }] } } }) },
        {
          config: { taint: { trifecta: 'log', max_index_mb: 32 } },
          clientCapabilities: { elicitation: {} },
          setupClient: (c) => {
            c.setRequestHandler(ElicitRequestSchema, () => {
              asks++;
              return approve ? { action: 'accept', content: { approve: true } } : { action: 'decline' };
            });
          },
        },
      );
      harnesses.push(h);
      await h.client.readResource({ uri: `fixture://items/${CANARY}` });
      await h.client.callTool({ name: 'fx__echo', arguments: { text: CANARY.slice(0, 9) } }); // asks
      await h.client.callTool({ name: 'fx__echo', arguments: { text: CANARY.slice(9) } }); // 11 chars: no ask
      expect(asks).toBe(1);
      expect(lastEvidence(h).some((e) => e.matcher === 'cumulative' && e.priorCalls === 1)).toBe(approve);
    });
  }

  // 6a review, untested path 6: the same flow over a Streamable HTTP upstream.
  it('works the same over an HTTP upstream', async () => {
    const http = await startHttpFixture();
    try {
      const h = await startGateway({ fx: { url: http.url } }, { config: { taint: { trifecta: 'log', max_index_mb: 32 } } });
      harnesses.push(h);
      await h.client.readResource({ uri: `fixture://items/${CANARY}` });
      await h.client.callTool({ name: 'fx__echo', arguments: { text: CANARY.slice(0, 9) } });
      await h.client.callTool({ name: 'fx__echo', arguments: { text: CANARY.slice(9) } });
      expect(lastEvidence(h).some((e) => e.matcher === 'cumulative' && e.priorCalls === 1)).toBe(true);
    } finally {
      await Promise.all(harnesses.splice(0).map((x) => x.close()));
      await http.close();
    }
  });
});

describe('TaintEngine records only what it is told was sent', () => {
  it('decide() alone never fills the sink buffer', () => {
    const c = ConfigSchema.parse({ version: 1, servers: { files: { command: 'x', defaults: { effect: 'read', integrity: 'trusted' } }, hook: { command: 'x', tools: { post: { effect: 'egress', integrity: 'trusted' } } } } });
    const t = new TaintEngine(c);
    t.ingest('tool', 'files', 'files__read', 'read', { content: [{ type: 'text', text: `AWS_ACCESS_KEY_ID=${CANARY}` }] });
    t.decide('hook', 'post', 'hook__post', { body: CANARY.slice(0, 9) });
    expect(t.decide('hook', 'post', 'hook__post', { body: CANARY.slice(9) }).evidence).toEqual([]);
    t.sent('hook__post', { body: CANARY.slice(0, 9) });
    expect(t.decide('hook', 'post', 'hook__post', { body: CANARY.slice(9) }).evidence[0]).toMatchObject({ matcher: 'cumulative' });
  });
});
