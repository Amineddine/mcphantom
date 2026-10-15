/**
 * Exfiltration channels at the decision level (Phase 6b PR 4b, owner spec): no servers, no network.
 * The session state is built directly (an untrusted output holding an inert marker, a trusted output
 * holding a fragment-built canary), then one tools/call per channel goes to the gate.
 */
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { ConfigSchema } from '../src/config/schema.js';
import { TaintEngine } from '../src/taint/engine.js';

const CANARY = ['AKIA', 'CHANNELCANARY', '042'].join('');
const B62 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const UNFORMATTED = Array.from(crypto.createHash('sha256').update('channel-unformatted').digest(), (b) => B62[b % 62]).join('').slice(0, 32);
const WORKSPACE = path.join(os.tmpdir(), 'mcphantom-ws');
const OUTSIDE = path.join(os.tmpdir(), 'mcphantom-synced', 'notes.txt');
const out = (t: string) => ({ content: [{ type: 'text', text: t }] });

function session(secretText: string, extra: Record<string, unknown> = {}): TaintEngine {
  const t = new TaintEngine(
    ConfigSchema.parse({
      version: 1,
      servers: {
        src: { command: 'x', tools: { note: { effect: 'read', integrity: 'untrusted' }, vault: { effect: 'read', integrity: 'trusted', confidentiality: 'internal' } } },
        net: { command: 'x', tools: { fetch: { effect: 'egress', integrity: 'untrusted' } } },
        hook: { command: 'x', tools: { notify: { effect: 'egress', integrity: 'trusted' } } },
        fs: { command: 'x', tools: { write_file: { effect: 'write', integrity: 'trusted', workspace: WORKSPACE } } },
      },
      ...extra,
    }),
  );
  t.ingest('tool', 'src', 'src__note', 'note', out('[[UNTRUSTED_PLACEHOLDER]]'));
  t.ingest('tool', 'src', 'src__vault', 'vault', out(secretText));
  return t;
}
const matchers = (d: { evidence: { matcher: string }[] }) => d.evidence.map((e) => e.matcher);

describe('exfiltration channels: one tools/call to the gate', () => {
  it('secret in a URL query string → deny (trifecta), exact evidence', () => {
    const d = session(`key=${CANARY}`).decide('net', 'fetch', 'net__fetch', { url: `http://127.0.0.1:9/p?d=${CANARY}` });
    expect(d).toMatchObject({ verdict: 'deny', rule: 'trifecta' });
    expect(matchers(d)).toContain('exact');
  });

  it('secret base64-encoded in a URL query parameter → deny, decoded evidence', () => {
    const d = session(`key=${CANARY}`).decide('net', 'fetch', 'net__fetch', { url: `http://127.0.0.1:9/p?d=${Buffer.from(CANARY).toString('base64url')}` });
    expect(d).toMatchObject({ verdict: 'deny', rule: 'trifecta' });
    expect(matchers(d)).toContain('decoded');
  });

  // Was a KNOWN GAP found by this file (6b PR 4b): base64 inside a URL *path segment* was not attributed
  // by Layer 2 (the trifecta still blocked). Closed in 6b PR 6.
  it('secret base64-encoded in a URL path segment → deny, decoded evidence', () => {
    const d = session(`key=${CANARY}`).decide('net', 'fetch', 'net__fetch', { url: `http://127.0.0.1:9/i/${Buffer.from(CANARY).toString('base64url')}.png` });
    expect(d).toMatchObject({ verdict: 'deny', rule: 'trifecta' });
    expect(matchers(d)).toContain('decoded');
  });

  // Found while closing the gap above (6b PR 6): only pattern-detected secrets and e-mails survived
  // decoding inside a URL; an unformatted token fused with `d=` and was not attributed.
  it('unformatted token base64-encoded in a URL query parameter → decoded evidence', () => {
    const d = session(UNFORMATTED).decide('hook', 'notify', 'hook__notify', { url: `http://127.0.0.1:9/p?d=${Buffer.from(UNFORMATTED).toString('base64url')}&n=1` });
    expect(matchers(d)).toContain('decoded');
  });

  it('secret split across two calls → deny, cumulative evidence on the completing call', () => {
    const t = session(`key=${CANARY}`);
    t.sent('net__fetch', { url: `http://127.0.0.1:9/p?d=${CANARY.slice(0, 10)}` });
    const d = t.decide('net', 'fetch', 'net__fetch', { url: CANARY.slice(10) });
    expect(d).toMatchObject({ verdict: 'deny', rule: 'trifecta' });
    expect(matchers(d)).toContain('cumulative');
  });

  it('write to a path outside the workspace → treated as egress → deny', () => {
    const d = session(`key=${CANARY}`).decide('fs', 'write_file', 'fs__write_file', { path: OUTSIDE, text: CANARY });
    expect(d).toMatchObject({ verdict: 'deny', rule: 'trifecta', effect: 'egress' });
    // ...while a write inside the workspace stays a write and is allowed.
    expect(session(`key=${CANARY}`).decide('fs', 'write_file', 'fs__write_file', { path: path.join(WORKSPACE, 'a.txt'), text: 'ok' }).verdict).toBe('allow');
  });

  it('a second, trusted egress tool → deny (the trifecta ignores the tool\'s own trust)', () => {
    const d = session(`key=${CANARY}`).decide('hook', 'notify', 'hook__notify', { body: CANARY });
    expect(d).toMatchObject({ verdict: 'deny', rule: 'trifecta' });
    expect(matchers(d)).toContain('exact');
  });

  it('unformatted secret: default record → allowed (published bypass); on_hit: secret → deny', () => {
    const recorded = session(UNFORMATTED).decide('hook', 'notify', 'hook__notify', { body: UNFORMATTED });
    expect(recorded.verdict).toBe('allow');
    expect(recorded.evidence.length).toBeGreaterThan(0); // attributed, but the context was never secret
    const escalated = session(UNFORMATTED, { secrets: { entropy: { on_hit: 'secret' } } }).decide('hook', 'notify', 'hook__notify', { body: UNFORMATTED });
    expect(escalated).toMatchObject({ verdict: 'deny', rule: 'trifecta' });
  });
});
