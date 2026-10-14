/**
 * Carried items closed before Phase 6 (owner): three places that contradicted fail-closed.
 *  1. The event log can be made a control: `logging.on_failure: deny` refuses requests it cannot audit.
 *  2. The policy deadline covers the whole evaluation, not only the custom predicates.
 *  3. An unlisted, untemplated resource URI is refused by default instead of routed to a sole server.
 */
import { afterEach, describe, expect, it } from 'vitest';
import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { CreateMessageRequestSchema, ElicitRequestSchema, ListRootsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { PolicyEngine, EVAL_BUDGET_MS } from '../src/policy/engine.js';
import type { EventInput } from '../src/store/store.js';
import { fixtureServer, makeConfig, startGateway, textOf, type GatewayHarness } from './helpers.js';

const harnesses: GatewayHarness[] = [];
afterEach(async () => {
  await Promise.all(harnesses.splice(0).map((h) => h.close()));
});
async function gw(...a: Parameters<typeof startGateway>): Promise<GatewayHarness> {
  const h = await startGateway(...a);
  harnesses.push(h);
  return h;
}

/** Makes the store throw for events of the given kinds (a full disk, a locked database, ...). */
function breakStore(h: GatewayHarness, kinds: EventInput['kind'][]): () => void {
  const real = h.store.append.bind(h.store);
  h.store.append = (e: EventInput) => {
    if (kinds.includes(e.kind)) throw new Error('SQLITE_FULL: database or disk is full');
    real(e);
  };
  return () => {
    h.store.append = real;
  };
}

const logging = (on_failure: 'warn' | 'deny') => ({ logging: { payloads: 'redacted', max_payload_bytes: 65_536, level: 'info', on_failure } });

describe('event log: logging.on_failure', () => {
  it('defaults to warn: a failing audit log does not stop calls', async () => {
    expect(makeConfig({ servers: {} }).logging.on_failure).toBe('warn');
    const h = await gw({ fx: fixtureServer('everything') });
    breakStore(h, ['decision', 'taint', 'request']);
    const r = await h.client.callTool({ name: 'fx__echo', arguments: { text: 'hi' } });
    expect(textOf(r)).toContain('hi');
  });

  it('deny: a call whose decision cannot be audited is refused before it reaches the server', async () => {
    const h = await gw({ fx: fixtureServer('everything') }, { config: logging('deny') });
    breakStore(h, ['decision']);
    await expect(h.client.callTool({ name: 'fx__echo', arguments: { text: 'hi' } })).rejects.toThrow(/audit log could not be written/);
    // Ingestion is recorded only after the upstream answered; nothing was ingested, so nothing was sent.
    expect(h.store.events({ kind: 'taint' })).toHaveLength(0);
  });

  it('deny: a result that cannot be audited is withheld from the client', async () => {
    const h = await gw({ fx: fixtureServer('everything') }, { config: logging('deny') });
    breakStore(h, ['taint']);
    await expect(h.client.callTool({ name: 'fx__echo', arguments: { text: 'secret-ish' } })).rejects.toThrow(/audit log could not be written/);
  });

  it('deny: a resource read that cannot be audited is refused', async () => {
    const h = await gw({ fx: fixtureServer('everything') }, { config: logging('deny') });
    breakStore(h, ['request', 'taint']);
    await expect(h.client.readResource({ uri: 'fixture://readme' })).rejects.toThrow(/audit log could not be written/);
  });

  // 6a review, untested path 1: every other request kind. "Refused" must mean the upstream never saw
  // the request: prompt arguments, completion values and URIs all carry data to the server.
  describe('deny: requests other than tools/call never reach the server unaudited', () => {
    const stats = async (h: GatewayHarness) => JSON.parse(textOf(await h.client.callTool({ name: 'fx__stats', arguments: {} }))) as Record<string, number>;

    it('prompts/get', async () => {
      const h = await gw({ fx: fixtureServer('everything') }, { config: logging('deny') });
      const restore = breakStore(h, ['request']);
      await expect(h.client.getPrompt({ name: 'fx__greet', arguments: { name: 'bob' } })).rejects.toThrow(/audit log could not be written/);
      restore();
      expect((await stats(h)).prompts).toBe(0);
    });

    it('completion/complete', async () => {
      const h = await gw({ fx: fixtureServer('everything') }, { config: logging('deny') });
      const restore = breakStore(h, ['request']);
      await expect(h.client.complete({ ref: { type: 'ref/prompt', name: 'fx__greet' }, argument: { name: 'name', value: 'al' } })).rejects.toThrow(/audit log could not be written/);
      restore();
      expect((await stats(h)).completions).toBe(0);
    });

    it('resources/subscribe', async () => {
      const h = await gw({ fx: fixtureServer('everything') }, { config: logging('deny') });
      const restore = breakStore(h, ['request']);
      await expect(h.client.subscribeResource({ uri: 'fixture://readme' })).rejects.toThrow(/audit log could not be written/);
      restore();
      expect((await stats(h)).subscribes).toBe(0);
    });

    it('resources/read of a templated URI (the URI itself can carry data)', async () => {
      const h = await gw({ fx: fixtureServer('everything') }, { config: logging('deny') });
      const restore = breakStore(h, ['request']);
      await expect(h.client.readResource({ uri: 'fixture://items/7' })).rejects.toThrow(/audit log could not be written/);
      restore();
      expect((await stats(h)).reads).toBe(0);
    });

    it('each still works while the log works, and is recorded before it is forwarded', async () => {
      const h = await gw({ fx: fixtureServer('everything') }, { config: logging('deny') });
      await h.client.getPrompt({ name: 'fx__greet', arguments: { name: 'bob' } });
      await h.client.complete({ ref: { type: 'ref/prompt', name: 'fx__greet' }, argument: { name: 'name', value: 'al' } });
      await h.client.subscribeResource({ uri: 'fixture://readme' });
      expect(await stats(h)).toMatchObject({ prompts: 1, completions: 1, subscribes: 1 });
      const forwarded = h.store.events({ kind: 'request' }).filter((e) => e.outcome === 'forwarding').map((e) => e.method);
      expect(forwarded).toEqual(expect.arrayContaining(['prompts/get', 'completion/complete', 'resources/subscribe']));
    });
  });

  describe('deny: server→client requests are not relayed unaudited', () => {
    const caps = { elicitation: {}, sampling: {}, roots: {} };
    const setupClient = (seen: string[]) => (c: Client) => {
      c.setRequestHandler(ElicitRequestSchema, () => {
        seen.push('elicitation');
        return { action: 'decline' };
      });
      c.setRequestHandler(CreateMessageRequestSchema, () => {
        seen.push('sampling');
        return { role: 'assistant', content: { type: 'text', text: 'x' }, model: 'm' };
      });
      c.setRequestHandler(ListRootsRequestSchema, () => {
        seen.push('roots');
        return { roots: [] };
      });
    };

    for (const [tool, args] of [['ask', {}], ['sample', { prompt: 'hi' }], ['roots', {}]] as const) {
      it(`${tool}: the client never sees the relayed request`, async () => {
        const seen: string[] = [];
        const h = await gw({ fx: fixtureServer('everything', { allow_sampling: true }) }, { config: logging('deny'), clientCapabilities: caps, setupClient: setupClient(seen) });
        breakStore(h, ['request']);
        // The tool's own result is withheld too (its request event cannot be written either).
        await expect(h.client.callTool({ name: `fx__${tool}`, arguments: args })).rejects.toThrow();
        expect(seen).toEqual([]);
      });
    }

    it('relays normally while the log works', async () => {
      const seen: string[] = [];
      const h = await gw({ fx: fixtureServer('everything', { allow_sampling: true }) }, { config: logging('deny'), clientCapabilities: caps, setupClient: setupClient(seen) });
      for (const [tool, args] of [['ask', {}], ['sample', { prompt: 'hi' }], ['roots', {}]] as const) await h.client.callTool({ name: `fx__${tool}`, arguments: args });
      expect(seen.sort()).toEqual(['elicitation', 'roots', 'sampling']);
    });
  });

  it('deny: requests are served normally while the log works', async () => {
    const h = await gw({ fx: fixtureServer('everything') }, { config: logging('deny') });
    expect(textOf(await h.client.callTool({ name: 'fx__echo', arguments: { text: 'hi' } }))).toContain('hi');
  });
});

describe('policy: the deadline covers the whole evaluation', () => {
  const config = makeConfig({
    servers: {
      mail: {
        command: 'x',
        tools: { send: { effect: 'egress', integrity: 'trusted', rules: [{ allow: 'arg.to == "a"' }, { allow: 'arg.to == "b"' }, { allow: 'arg.to == "c"' }] } },
      },
    },
    declassify: [{ id: 'ok', tool: 'mail__send', when: 'arg.to == "a"', reason: 'test' }],
  });
  const inputs = { serverId: 'mail', toolName: 'send', args: { to: 'a' }, context: { integrity: 'trusted', confidentiality: 'public' }, provenanceOf: () => new Set<'trusted' | 'untrusted'>() } as const;

  it('time spent in plain CEL (no custom predicate) counts: an overrun denies', () => {
    const engine = new PolicyEngine(config);
    // Each clock read advances 30 ms, as if every expression were slow. No custom predicate runs here,
    // so before this fix the budget was never checked and all three rules matched.
    let t = 0;
    engine.now = () => (t += 30);
    const o = engine.evaluate(inputs);
    expect(o.effect).toBe('deny');
    expect(o.errors.map((e) => e.message).join()).toMatch(/exceeded its time budget/);
  });

  it('an overrun during declassify conditions denies and lifts nothing', () => {
    const engine = new PolicyEngine(config);
    let reads = 0;
    // Fast through the rules, then the clock jumps past the deadline.
    engine.now = () => (++reads > 5 ? 10 * EVAL_BUDGET_MS : 0); // reads: start, 3 rules, 1 declassify, then the final check
    const o = engine.evaluate(inputs);
    expect(o.effect).toBe('deny');
    expect(o.declassified).toBeUndefined();
  });

  // 6a review, untested path 2: the deadline under a real clock, with genuinely slow CEL (no custom
  // predicate, no injected clock). CEL cannot be pre-empted, so the evaluation runs to completion and
  // is then denied: the deadline bounds what is *allowed*, not how long evaluation takes.
  it('real clock: a genuinely slow CEL rule (quadratic over a list) denies', () => {
    const slow = makeConfig({
      servers: { s: { command: 'x', tools: { t: { effect: 'egress', integrity: 'trusted', rules: [{ deny: 'arg.items.exists(x, arg.items.exists(y, x + y == "never"))' }] } } } },
    });
    const run = (n: number) =>
      new PolicyEngine(slow).evaluate({
        serverId: 's', toolName: 't', args: { items: Array.from({ length: n }, (_, i) => `item-${i}`) },
        context: { integrity: 'trusted', confidentiality: 'public' }, provenanceOf: () => new Set(),
      });
    const o = run(500); // ~0.5 s on the development laptop; still far above 50 ms on a fast runner
    expect(o.effect).toBe('deny');
    expect(o.errors.map((e) => e.message).join()).toMatch(/exceeded its time budget/);
    // The same rule on a small list is fast and does not match: the deny above is the deadline's.
    expect(run(10)).toMatchObject({ effect: undefined, errors: [] });
  });

  it('a normal evaluation is unaffected', () => {
    const o = new PolicyEngine(config).evaluate(inputs);
    expect(o).toMatchObject({ effect: 'allow', errors: [], declassified: { id: 'ok' } });
  });
});

describe('resources: unrouted URIs', () => {
  it('defaults to deny: an unlisted, untemplated URI is not guessed onto the only resource server', async () => {
    const h = await gw({ fx: fixtureServer('everything') });
    await expect(h.client.readResource({ uri: 'file:///etc/passwd' })).rejects.toThrow(/no server provides resource/);
  });

  it('listed and templated URIs still route', async () => {
    const h = await gw({ fx: fixtureServer('everything') });
    expect((await h.client.readResource({ uri: 'fixture://readme' })).contents[0]).toMatchObject({ text: 'fixture readme' });
    expect((await h.client.readResource({ uri: 'fixture://items/7' })).contents[0]).toMatchObject({ text: '{"id":"7"}' });
  });

  it('sole-server is an explicit opt-in: the URI is then sent to the only resource-capable server', async () => {
    const h = await gw({ fx: fixtureServer('everything') }, { config: { resources: { unrouted: 'sole-server' } } });
    // The fixture does not know this URI, so the error now comes from the upstream server, not the router.
    await expect(h.client.readResource({ uri: 'fixture://unlisted' })).rejects.toThrow(/not found/i);
  });
});
