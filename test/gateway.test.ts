import { afterEach, describe, expect, it } from 'vitest';
import {
  CreateMessageRequestSchema,
  ElicitRequestSchema,
  ListRootsRequestSchema,
  LoggingMessageNotificationSchema,
  ToolListChangedNotificationSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { fixtureServer, startGateway, startHttpFixture, textOf, type GatewayHarness } from './helpers.js';

const harnesses: GatewayHarness[] = [];
async function gw(...args: Parameters<typeof startGateway>): Promise<GatewayHarness> {
  const h = await startGateway(...args);
  harnesses.push(h);
  return h;
}
afterEach(async () => {
  await Promise.all(harnesses.splice(0).map((h) => h.close()));
});

describe('gateway: routing and namespacing', () => {
  it('multiplexes several servers under distinct prefixes', async () => {
    const h = await gw({ a: fixtureServer('everything'), b: fixtureServer('paginated') });
    const names = (await h.client.listTools()).tools.map((t) => t.name);
    expect(names).toContain('a__echo');
    expect(names).toContain('b__t9');
    expect(textOf(await h.client.callTool({ name: 'b__t5', arguments: {} }))).toBe('called t5');
  });

  it('hides tools whose namespaced name would exceed MCP limits, and records why', async () => {
    const h = await gw({ fx: fixtureServer('everything') });
    const names = (await h.client.listTools()).tools.map((t) => t.name);
    expect(names.some((n) => n.includes('xxxxxxxx'))).toBe(false);
    const warnings = h.store.events({ kind: 'warning' });
    expect(warnings.some((w) => w.error?.includes('cannot be namespaced'))).toBe(true);
  });

  it('rejects unknown tools and malformed names with InvalidParams', async () => {
    const h = await gw({ fx: fixtureServer('everything') });
    for (const name of ['fx__nope', 'nope', '__echo', 'other__echo', 'FX__echo']) {
      await expect(h.client.callTool({ name, arguments: {} })).rejects.toMatchObject({ code: -32602 });
    }
  });

  it('allows calling a tool before tools/list (re-lists on demand)', async () => {
    const h = await gw({ fx: fixtureServer('everything') });
    expect(textOf(await h.client.callTool({ name: 'fx__echo', arguments: { text: 'x' } }))).toBe('x');
  });

  it('rejects a cursor it never issued', async () => {
    const h = await gw({ fx: fixtureServer('everything') });
    await expect(h.client.listTools({ cursor: 'forged' })).rejects.toMatchObject({ code: -32602 });
  });
});

describe('gateway: pagination', () => {
  it('fetches every upstream page and returns them as one listing', async () => {
    const h = await gw({ p: fixtureServer('paginated') });
    const r = await h.client.listTools();
    expect(r.tools.map((t) => t.name)).toEqual(['p__t1', 'p__t2', 'p__t3', 'p__t4', 'p__t5', 'p__t6', 'p__t7', 'p__t8', 'p__t9']);
    expect(r.nextCursor).toBeUndefined();
  });

  it('detects a cursor cycle instead of looping, and drops that server from the listing', async () => {
    const h = await gw({ p: fixtureServer('paginated', { env: { PAGINATE_MODE: 'cycle' } }), fx: fixtureServer('everything') });
    const names = (await h.client.listTools()).tools.map((t) => t.name);
    expect(names.some((n) => n.startsWith('p__'))).toBe(false);
    expect(names).toContain('fx__echo');
    expect(h.store.events({ kind: 'warning' }).some((w) => w.error?.includes('repeated cursor'))).toBe(true);
  });
});

describe('gateway: progress and cancellation', () => {
  it('relays progress notifications under the client’s own token', async () => {
    const h = await gw({ fx: fixtureServer('everything') });
    const seen: number[] = [];
    const r = await h.client.callTool({ name: 'fx__slow', arguments: { steps: 4 } }, undefined, {
      onprogress: (p) => seen.push(p.progress),
    });
    expect(textOf(r)).toBe('done 4');
    expect(seen).toEqual([1, 2, 3, 4]);
  });

  it('propagates client cancellation to the upstream server', async () => {
    const h = await gw({ fx: fixtureServer('everything') });
    const ac = new AbortController();
    const pending = h.client.callTool({ name: 'fx__slow', arguments: { steps: 50, delayMs: 20 } }, undefined, {
      signal: ac.signal,
      onprogress: (p) => {
        if (p.progress === 2) ac.abort();
      },
    });
    await expect(pending).rejects.toThrow();
    // Give the cancellation notification time to reach the upstream and the loop to observe it.
    await new Promise((r) => setTimeout(r, 300));
    const stats = JSON.parse(textOf(await h.client.callTool({ name: 'fx__stats', arguments: {} }))) as { cancelled: number };
    expect(stats.cancelled).toBeGreaterThanOrEqual(1);
  });
});

describe('gateway: server→client requests', () => {
  it('denies sampling by default even when the client supports it, and records the denial', async () => {
    let sampled = false;
    const h = await gw({ fx: fixtureServer('everything') }, {
      clientCapabilities: { sampling: {} },
      setupClient: (c) => {
        c.setRequestHandler(CreateMessageRequestSchema, () => {
          sampled = true;
          return { role: 'assistant', content: { type: 'text', text: 'LEAK' }, model: 'm' };
        });
      },
    });
    const r = await h.client.callTool({ name: 'fx__sample', arguments: { prompt: 'hi' } });
    expect(r.isError).toBe(true);
    expect(sampled).toBe(false);
    expect(h.store.events({ kind: 'denied' }).some((e) => e.method === 'sampling/createMessage')).toBe(true);
  });

  it('relays sampling when allow_sampling is set for that server', async () => {
    const h = await gw({ fx: fixtureServer('everything', { allow_sampling: true }) }, {
      clientCapabilities: { sampling: {} },
      setupClient: (c) => {
        c.setRequestHandler(CreateMessageRequestSchema, () => ({ role: 'assistant', content: { type: 'text', text: 'pong' }, model: 'm' }));
      },
    });
    expect(textOf(await h.client.callTool({ name: 'fx__sample', arguments: { prompt: 'ping' } }))).toBe('sampled: pong');
  });

  it('relays elicitation and roots to a client that supports them', async () => {
    const h = await gw({ fx: fixtureServer('everything') }, {
      clientCapabilities: { elicitation: {}, roots: { listChanged: true } },
      setupClient: (c) => {
        c.setRequestHandler(ElicitRequestSchema, () => ({ action: 'accept', content: { name: 'Ada' } }));
        c.setRequestHandler(ListRootsRequestSchema, () => ({ roots: [{ uri: 'file:///work', name: 'work' }] }));
      },
    });
    expect(textOf(await h.client.callTool({ name: 'fx__ask', arguments: {} }))).toBe('elicited: accept {"name":"Ada"}');
    expect(JSON.parse(textOf(await h.client.callTool({ name: 'fx__roots', arguments: {} })))).toEqual([{ uri: 'file:///work', name: 'work' }]);
  });

  it('refuses roots when the client does not support them', async () => {
    const h = await gw({ fx: fixtureServer('everything') });
    const r = await h.client.callTool({ name: 'fx__roots', arguments: {} });
    expect(r.isError).toBe(true);
    expect(textOf(r)).toContain('does not support roots');
  });

  it('relays upstream log messages with the server id as logger, honouring setLevel', async () => {
    const logs: { level: string; logger?: string | undefined }[] = [];
    const h = await gw({ fx: fixtureServer('everything') }, {
      setupClient: (c) => {
        c.setNotificationHandler(LoggingMessageNotificationSchema, (n) => {
          logs.push({ level: n.params.level, logger: n.params.logger });
        });
      },
    });
    await h.client.setLoggingLevel('warning');
    await h.client.callTool({ name: 'fx__log', arguments: { level: 'info' } });
    await h.client.callTool({ name: 'fx__log', arguments: { level: 'error' } });
    await new Promise((r) => setTimeout(r, 100));
    expect(logs).toEqual([{ level: 'error', logger: 'fx/fixture' }]);
  });
});

describe('gateway: unknown methods fail closed', () => {
  it('rejects methods it has no handler for, and records the denial', async () => {
    const h = await gw({ fx: fixtureServer('everything') });
    await expect(h.client.request({ method: 'tasks/list', params: {} }, z.object({}).loose())).rejects.toMatchObject({ code: -32601 });
    await expect(h.client.request({ method: 'x-vendor/backdoor', params: {} }, z.object({}).loose())).rejects.toMatchObject({ code: -32601 });
    expect(h.store.events({ kind: 'denied' }).map((e) => e.method)).toEqual(expect.arrayContaining(['tasks/list', 'x-vendor/backdoor']));
  });
});

describe('gateway: upstream failures', () => {
  it('keeps serving other servers when one fails to start', async () => {
    const h = await gw({ bad: { command: 'definitely-not-a-real-binary-mcphantom' }, fx: fixtureServer('everything') });
    const names = (await h.client.listTools()).tools.map((t) => t.name);
    expect(names).toContain('fx__echo');
    expect(names.some((n) => n.startsWith('bad__'))).toBe(false);
    expect(h.store.events({ kind: 'upstream_failed' }).map((e) => e.server)).toEqual(['bad']);
  });

  it('times out a server that never completes initialization', async () => {
    const t0 = Date.now();
    const h = await gw({ silent: fixtureServer('silent', { startup_timeout_ms: 1500 }), fx: fixtureServer('everything') });
    expect(Date.now() - t0).toBeLessThan(15_000);
    const failed = h.store.events({ kind: 'upstream_failed' });
    expect(failed[0]?.error).toContain('within 1500 ms');
  });

  it('handles an upstream crash mid-call: error to the client, list_changed, server removed', async () => {
    let listChanged = 0;
    const h = await gw({ c: fixtureServer('crash'), fx: fixtureServer('everything') }, {
      setupClient: (c) => {
        c.setNotificationHandler(ToolListChangedNotificationSchema, () => {
          listChanged++;
        });
      },
    });
    await h.client.listTools();
    await expect(h.client.callTool({ name: 'c__die', arguments: {} })).rejects.toThrow();
    await new Promise((r) => setTimeout(r, 300));
    expect(listChanged).toBeGreaterThanOrEqual(1);
    const names = (await h.client.listTools()).tools.map((t) => t.name);
    expect(names.some((n) => n.startsWith('c__'))).toBe(false);
    await expect(h.client.callTool({ name: 'c__alive', arguments: {} })).rejects.toMatchObject({ code: -32602 });
    expect(textOf(await h.client.callTool({ name: 'fx__echo', arguments: { text: 'still up' } }))).toBe('still up');
  });
});

describe('gateway: Streamable HTTP upstream', () => {
  it('proxies an HTTP server and forwards configured headers', async () => {
    const http = await startHttpFixture('Bearer s3cr3t-token-value');
    try {
      const h = await gw({ web: { type: 'http', url: http.url, headers: { Authorization: 'Bearer s3cr3t-token-value' } } }, { knownSecrets: ['Bearer s3cr3t-token-value'] });
      expect(textOf(await h.client.callTool({ name: 'web__echo', arguments: { text: 'over http' } }))).toBe('over http');
    } finally {
      await http.close();
    }
  });

  it('reports an HTTP server that rejects the credentials as failed', async () => {
    const http = await startHttpFixture('Bearer right');
    try {
      const h = await gw({ web: { type: 'http', url: http.url, headers: { Authorization: 'Bearer wrong' } } });
      expect(h.store.events({ kind: 'upstream_failed' }).map((e) => e.server)).toEqual(['web']);
    } finally {
      await http.close();
    }
  });
});

describe('gateway: event log redaction', () => {
  it('never stores a configured secret or a detected credential, in params or results', async () => {
    const secret = 'sk-ant-api03-THISISAFAKEKEYFORTESTS0123456789abcdef';
    const h = await gw({ fx: fixtureServer('everything', { env: { FIXTURE_SECRET: secret } }) }, { knownSecrets: [secret] });
    const r = await h.client.callTool({ name: 'fx__env', arguments: {} });
    expect(textOf(r)).toBe(`secret=${secret}`); // the client still gets the real output
    await h.client.callTool({ name: 'fx__echo', arguments: { text: 'my key is AKIAIOSFODNN7EXAMPLE and ghp_' + 'a'.repeat(36) } });
    const all = JSON.stringify(h.store.events());
    expect(all).not.toContain(secret);
    expect(all).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(all).not.toContain('a'.repeat(36));
    expect(all).toContain('[REDACTED:');
  });
});
