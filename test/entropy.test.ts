/**
 * Entropy-based possible-secret detection (Phase 6b). Owner constraint: an entropy-only hit never
 * raises the label to `secret` unless `secrets.entropy.on_hit` says so; hash-shaped hits never do.
 * Secret-shaped test values are generated at runtime so the repository carries none.
 */
import { describe, expect, it } from 'vitest';
import { ConfigSchema } from '../src/config/schema.js';
import { findSecrets } from '../src/secrets/detectors.js';
import { classifyToken, findPossibleSecrets, MAX_TOKEN } from '../src/secrets/entropy.js';
import { Redactor } from '../src/secrets/redact.js';
import { TaintEngine } from '../src/taint/engine.js';

function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const B62 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const B57 = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
const rand = (n: number, alpha = B62, seed = 1) => {
  const r = rng(seed);
  return Array.from({ length: n }, () => alpha[Math.floor(r() * alpha.length)]).join('');
};
const RANDOM = rand(40);
const UUID = '3f2b8c1e-9a4d-4e7b-b1c2-5d6e7f809a1b';

describe('classifyToken', () => {
  it.each([
    ['a UUID', UUID, 'hash'],
    ['a commit SHA', '9fceb02d0ae598e95dc970b74767f19372d61af8', 'hash'],
    ['a SHA-256 digest', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'hash'],
    ['a typed hex id', 'subnet-0a1b2c3d4e5f60718', 'hash'],
    ['an SRI integrity value', 'sha512-' + rand(86, B62 + '+/', 3) + '==', 'hash'],
    ['a long number (hex subset: recorded only)', '12345678901234567890123', 'hash'],
    ['random base62', RANDOM, 'random'],
    ['random base57 (PostHog key body)', rand(48, B57, 2), 'random'],
  ])('%s → %s', (_n, token, shape) => {
    expect(classifyToken(token)).toBe(shape);
  });

  it.each([
    ['camelCase identifier', 'getElementByIdForTestingPurposes'],
    ['SCREAMING_SNAKE constant', 'MCPHANTOM_MAX_INDEX_BYTES_DEFAULT'],
    ['letters only', 'abcdefghijklmnopqrstuvwxyzABCDEF'],
    ['low entropy', 'aaaaaaaaaa1111111111bbbbbbbbbb'],
    ['too short', rand(19)],
    ['too long (a blob)', rand(MAX_TOKEN + 1)],
  ])('%s → not a possible secret', (_n, token) => {
    expect(classifyToken(token)).toBeUndefined();
  });
});

describe('findPossibleSecrets: tokenisation', () => {
  it('splits key=value and keeps base64 padding', () => {
    const b64 = Buffer.from(rand(30, B62, 5)).toString('base64');
    const hits = findPossibleSecrets(`request_id=${RANDOM} blob ${b64}`);
    expect(hits.map((h) => h.shape)).toEqual(['random', 'random']);
    expect(`request_id=${RANDOM}`.slice(hits[0]?.start, hits[0]?.end)).toBe(RANDOM);
  });

  it('splits paths and names at separators when a component is a word', () => {
    expect(findPossibleSecrets(`exports/billing/${UUID}.parquet`)).toEqual([expect.objectContaining({ shape: 'hash' })]);
    expect(findPossibleSecrets('ReplicaSet/worker-3qcavhgym4 reports-oh5yspwmkg-kwlb7')).toEqual([]);
  });

  it('does not split random base64url that happens to contain separators', () => {
    const t = rand(20, B62, 9) + '-' + rand(22, B62, 10);
    expect(findPossibleSecrets(t)).toEqual([expect.objectContaining({ shape: 'random' })]);
  });

  it('is linear on adversarial input (1 MB run, 1 MB of near-miss tokens)', () => {
    const t0 = performance.now();
    findPossibleSecrets('a1'.repeat(512 * 1024));
    findPossibleSecrets(Array.from({ length: 50_000 }, (_, i) => `x${i}y-billing-${i}`).join(' '));
    expect(performance.now() - t0).toBeLessThan(3000);
  });
});

describe('posthog-key rule', () => {
  it('matches personal and secret keys, not the public project token', () => {
    const body = rand(48, B57, 4);
    for (const prefix of ['phx', 'phs', 'pha', 'phr']) expect(findSecrets(`key ${prefix}_${body} end`).map((m) => m.rule)).toContain('posthog-key');
    expect(findSecrets(`posthog.init('phc_${body}')`).some((m) => m.rule === 'posthog-key')).toBe(false);
  });
});

describe('Redactor: possible secrets', () => {
  it('redacts random and hash-shaped tokens by default, keeps known rules named', () => {
    const r = new Redactor();
    const aws = ['AKIA', 'ENTROPYTESTKEY42'].join('');
    const out = r.redactString(`a ${RANDOM} b ${UUID} c ${aws}`);
    expect(out).toBe('a [REDACTED:possible-secret] b [REDACTED:possible-hash] c [REDACTED:aws-access-key-id]');
  });

  it('entropy: false leaves them', () => {
    expect(new Redactor({ entropy: false }).redactString(`a ${RANDOM} b`)).toBe(`a ${RANDOM} b`);
  });
});

describe('TaintEngine: secrets.entropy.on_hit', () => {
  const servers = { files: { command: 'x', defaults: { effect: 'read', integrity: 'trusted', confidentiality: 'public' } } };
  const engine = (entropy: Record<string, unknown> = {}) => new TaintEngine(ConfigSchema.parse({ version: 1, servers, secrets: { entropy } }));
  const out = (t: string) => ({ content: [{ type: 'text', text: t }] });

  it('default record: counted, label unchanged (owner constraint)', () => {
    const e = engine();
    const r = e.ingest('tool', 'files', 'files__read', 'read', out(`value: ${RANDOM}\nid: ${UUID}`));
    expect(r.possibleSecrets).toEqual({ random: 1, hash: 1 });
    expect(r.secretsDetected).toEqual([]);
    expect(e.context.confidentiality).toBe('public');
  });

  it('internal raises to internal; secret raises to secret', () => {
    const i = engine({ on_hit: 'internal' });
    i.ingest('tool', 'files', 'files__read', 'read', out(RANDOM));
    expect(i.context.confidentiality).toBe('internal');
    const s = engine({ on_hit: 'secret' });
    s.ingest('tool', 'files', 'files__read', 'read', out(RANDOM));
    expect(s.context.confidentiality).toBe('secret');
  });

  it('hash-shaped hits never raise the label, whatever on_hit says', () => {
    const e = engine({ on_hit: 'secret' });
    e.ingest('tool', 'files', 'files__read', 'read', out(`${UUID} 9fceb02d0ae598e95dc970b74767f19372d61af8`));
    expect(e.context.confidentiality).toBe('public');
  });

  it('a known-format secret is not counted again as a possible secret', () => {
    const e = engine();
    const r = e.ingest('tool', 'files', 'files__read', 'read', out(`phx_${rand(48, B57, 6)}`));
    expect(r.secretsDetected).toEqual(['posthog-key']);
    expect(r.possibleSecrets).toEqual({ random: 0, hash: 0 });
  });

  it('enabled: false turns detection off', () => {
    expect(engine({ enabled: false, on_hit: 'secret' }).ingest('tool', 'files', 'files__read', 'read', out(RANDOM)).possibleSecrets).toEqual({ random: 0, hash: 0 });
  });
});

describe('through the gateway', () => {
  it('a random token in a tool output is counted in the taint event and redacted in the log', async () => {
    const { fixtureServer, startGateway } = await import('./helpers.js');
    const h = await startGateway({ fx: fixtureServer('everything') });
    try {
      await h.client.callTool({ name: 'fx__echo', arguments: { text: `here: ${RANDOM}` } });
      const taint = h.store.events({ kind: 'taint' });
      const payload = JSON.parse(taint[taint.length - 1]?.payload ?? '{}') as { possibleSecrets?: unknown };
      expect(payload.possibleSecrets).toEqual({ random: 1, hash: 0 });
      const all = h.store.events({}).map((e) => `${e.payload ?? ''}${e.error ?? ''}`).join('\n');
      expect(all).not.toContain(RANDOM);
      expect(all).toContain('[REDACTED:possible-secret]');
    } finally {
      await h.close();
    }
  });
});
