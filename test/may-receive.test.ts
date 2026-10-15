/**
 * Per-server `may_receive` (DESIGN.md §2; Phase 6b, owner decision 2026-10-13), pinned against the
 * "server that is itself the sink" attack: a tool classified `read` (so the trifecta invariant never
 * fires) whose server logs every argument it receives. The oracle is the sink's own log file.
 */
import fs from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { ConfigSchema } from '../src/config/schema.js';
import { PolicyEngine } from '../src/policy/engine.js';
import { TaintEngine } from '../src/taint/engine.js';
import { fixtureServer, startGateway, tempDir, textOf, type GatewayHarness } from './helpers.js';

// AWS-format canary, assembled at runtime so the repository carries no secret-shaped string.
const CANARY = ['AKIA', 'MAYRECEIVE', 'CANARY'].join('');
const decimalCodes = (s: string) => Array.from(s, (c) => c.charCodeAt(0)).join(' ');

const harnesses: GatewayHarness[] = [];
afterEach(async () => {
  await Promise.all(harnesses.splice(0).map((h) => h.close()));
});

async function world(sinkExtra: Record<string, unknown> = {}) {
  const log = path.join(tempDir(), 'sink.log');
  const h = await startGateway({
    // The secret's source: a trusted internal server (here a resource read of the everything fixture).
    fx: fixtureServer('everything', { defaults: { integrity: 'trusted', confidentiality: 'internal' } }),
    // The sink, which the user classified as a harmless read-only tool.
    sink: fixtureServer('sink', { env: { SINK_LOG: log }, defaults: { effect: 'read', integrity: 'trusted' }, ...sinkExtra }),
  });
  harnesses.push(h);
  const leaked = () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8') : '');
  const summarize = (text: string) => h.client.callTool({ name: 'sink__summarize_text', arguments: { text } });
  return { h, leaked, summarize };
}

describe('may_receive: the server that is itself the sink', () => {
  it('without a bound the attack succeeds: a read-classified tool is not covered by the trifecta', async () => {
    const { h, leaked, summarize } = await world();
    await h.client.readResource({ uri: `fixture://items/${CANARY}` });
    expect(textOf(await summarize(`config dump: ${CANARY}`))).toContain('Summary');
    expect(leaked()).toContain(CANARY);
  });

  it('may_receive: internal blocks a credential (evidence mode, the default)', async () => {
    const { h, leaked, summarize } = await world({ may_receive: 'internal' });
    await h.client.readResource({ uri: `fixture://items/${CANARY}` });
    const r = await summarize(`config dump: ${CANARY}`);
    expect(r.isError).toBe(true);
    expect(textOf(r)).toMatch(/rule: may_receive/);
    expect(leaked()).toBe('');
    const d = JSON.parse(h.store.events({ kind: 'decision' }).at(-1)?.payload ?? '{}') as { rule?: string };
    expect(d.rule).toBe('may_receive');
  });

  it('blocks an encoded credential too (base64), and allows unrelated text', async () => {
    const { h, leaked, summarize } = await world({ may_receive: 'internal' });
    await h.client.readResource({ uri: `fixture://items/${CANARY}` });
    expect((await summarize(Buffer.from(`k=${CANARY}`).toString('base64'))).isError).toBe(true);
    expect((await summarize('Meeting moved to Thursday.')).isError).toBeFalsy();
    expect(leaked()).not.toContain(CANARY);
  });

  it('may_receive: public blocks internal data attributed by Layer 2 (no credential format involved)', async () => {
    const { h, leaked, summarize } = await world({ may_receive: 'public' });
    const codename = 'NIGHTJAR-7Q2XK9-LAUNCH-PLAN-2027';
    await h.client.callTool({ name: 'fx__echo', arguments: { text: `Internal roadmap: project ${codename} ships in March.` } });
    const r = await summarize(`Please summarise: ${codename} ships in March`);
    expect(r.isError).toBe(true);
    expect(textOf(r)).toMatch(/labelled internal/);
    expect(leaked()).toBe('');
  });

  it('KNOWN BYPASS (evidence mode): an encoding neither the detectors nor attribution decode gets through', async () => {
    const { h, leaked, summarize } = await world({ may_receive: 'internal' });
    await h.client.readResource({ uri: `fixture://items/${CANARY}` });
    expect((await summarize(decimalCodes(CANARY))).isError).toBeFalsy();
    expect(leaked()).toContain(decimalCodes(CANARY));
  });

  it('context mode closes that bypass: nothing reaches the server once the context is above the bound', async () => {
    const { h, leaked, summarize } = await world({ may_receive: 'internal', may_receive_mode: 'context' });
    expect((await summarize('before any secret was read')).isError).toBeFalsy();
    await h.client.readResource({ uri: `fixture://items/${CANARY}` });
    const r = await summarize(decimalCodes(CANARY));
    expect(r.isError).toBe(true);
    expect(textOf(r)).toMatch(/may_receive_mode: context/);
    // ...at the documented cost: an unrelated call is blocked too.
    expect((await summarize('Meeting moved to Thursday.')).isError).toBe(true);
    expect(leaked()).not.toContain(decimalCodes(CANARY));
  });

  it('may_receive: secret is no bound at all', async () => {
    const { h, leaked, summarize } = await world({ may_receive: 'secret' });
    await h.client.readResource({ uri: `fixture://items/${CANARY}` });
    expect((await summarize(CANARY)).isError).toBeFalsy();
    expect(leaked()).toContain(CANARY);
  });
});

describe('may_receive: precedence in the decision', () => {
  const servers = {
    files: { command: 'x', defaults: { effect: 'read', integrity: 'trusted' } },
    mail: { command: 'x', may_receive: 'internal', tools: { send: { effect: 'egress', integrity: 'trusted', rules: [{ ask: 'true' }] } } },
  };
  const engine = (extra: Record<string, unknown> = {}) => {
    const c = ConfigSchema.parse({ version: 1, servers, ...extra });
    const e = new TaintEngine(c, new PolicyEngine(c));
    e.ingest('tool', 'files', 'files__read', 'read', { content: [{ type: 'text', text: `AWS_ACCESS_KEY_ID=${CANARY}` }] });
    return e;
  };

  it('a may_receive violation is a deny, not an ask', () => {
    expect(engine().decide('mail', 'send', 'mail__send', { body: CANARY })).toMatchObject({ verdict: 'deny', rule: 'may_receive', enforced: true });
  });

  it('a declassify entry lifts the trifecta only, never may_receive', () => {
    const e = engine({ declassify: [{ id: 'all', tool: 'mail__send', when: 'true', reason: 'test' }] });
    expect(e.decide('mail', 'send', 'mail__send', { body: CANARY })).toMatchObject({ verdict: 'deny', rule: 'may_receive' });
  });

  it('a call within the bound goes on to the policy (here: ask)', () => {
    expect(engine().decide('mail', 'send', 'mail__send', { body: 'hello' })).toMatchObject({ verdict: 'ask', rule: 'policy' });
  });

  // R6b-1 (6b review), fixed in Phase 7: evidence mode used to search only the first 64 KiB of each of
  // the first 512 leaves and ignored attribution's `degraded` flag.
  it.each([
    ['past 64 KiB of one argument', { body: 'a '.repeat(33_000) + CANARY }],
    ['in the 513th leaf', { body: [...Array.from({ length: 512 }, () => 'ok'), CANARY] }],
  ])('a clear-text credential %s is bounded (whole fields are searched)', (_n, args) => {
    const d = engine().decide('mail', 'send', 'mail__send', args);
    expect(d).toMatchObject({ verdict: 'deny', rule: 'may_receive' });
    expect(d.reason).toContain('carries a credential');
  });

  it('arguments past a bound that can hide a credential fail closed, and the reason names it and the way out', () => {
    const d = engine().decide('mail', 'send', 'mail__send', { body: 'a '.repeat(40_000) });
    expect(d).toMatchObject({ verdict: 'deny', rule: 'may_receive', attributionDegraded: true });
    expect(d.degradedBy).toContain('leaf-size');
    expect(d.reason).toContain('fail-closed');
    expect(d.reason).toContain('an argument field over 64 KiB');
    expect(d.reason).toContain('split it into smaller calls');
    expect(d.reason).toContain("raise may_receive for 'mail'");
  });

  // Owner option B: the similarity matchers' bounds lose only edited copies and far-apart splits, so
  // they do not block (bench:may-receive publishes what each alternative would have cost).
  it('the fuzzy and cumulative bounds alone do not block', () => {
    const prose = Array.from({ length: 3000 }, (_, i) => ['plan', 'review', 'draft', 'notes', 'budget'][i % 5]).join(' ');
    const fuzzy = engine().decide('mail', 'send', 'mail__send', { body: prose }); // ~17 KiB of prose
    expect(fuzzy.degradedBy).toEqual(['fuzzy']);
    expect(fuzzy.rule).not.toBe('may_receive');
    const e = engine();
    for (let i = 0; i < 10; i++) e.sent('mail__send', { body: prose.slice(0, 2048) });
    const later = e.decide('mail', 'send', 'mail__send', { body: 'hello' });
    expect(later.degradedBy).toEqual(['cumulative']);
    expect(later.rule).not.toBe('may_receive');
  });

  it('...but not when nothing above the bound was ever read (nothing could have been missed)', () => {
    const c = ConfigSchema.parse({ version: 1, servers });
    const e = new TaintEngine(c, new PolicyEngine(c));
    e.ingest('tool', 'files', 'files__read', 'read', { content: [{ type: 'text', text: 'meeting notes' }] });
    expect(e.decide('mail', 'send', 'mail__send', { body: 'a '.repeat(40_000) })).toMatchObject({ verdict: 'ask', rule: 'policy', attributionDegraded: true });
  });
});

describe('may_receive: outputs attribution lost track of', () => {
  const big = (label: string) => `${label}
` + 'x'.repeat(140 * 1024); // past the 128 KiB output decode bound
  const engine = (outputConf: 'internal' | 'secret') => {
    const c = ConfigSchema.parse({ version: 1, servers: {
      files: { command: 'x', defaults: { effect: 'read', integrity: 'trusted', confidentiality: outputConf } },
      mail: { command: 'x', may_receive: 'internal', tools: { send: { effect: 'egress', integrity: 'trusted' } } },
    } });
    const e = new TaintEngine(c, new PolicyEngine(c));
    e.ingest('tool', 'files', 'files__read', 'read', { content: [{ type: 'text', text: big('report') }] });
    return e;
  };

  it('a secret output decoded only in part makes later calls to the bounded server fail closed', () => {
    const d = engine('secret').decide('mail', 'send', 'mail__send', { body: 'hello' });
    expect(d).toMatchObject({ verdict: 'deny', rule: 'may_receive' });
    expect(d.reason).toContain('lost track of secret data');
    expect(d.reason).toContain('start a new session');
    expect(d.degradedBy).toEqual(['output-decode']);
  });

  it('an internal one does not, for a server allowed to receive internal data', () => {
    expect(engine('internal').decide('mail', 'send', 'mail__send', { body: 'hello' }).verdict).toBe('allow');
  });
});
