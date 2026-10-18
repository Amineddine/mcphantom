/**
 * The ablation switches (Phase 7 item 4) exist for `bench:ablations` only. These tests pin that no
 * configuration can reach them, that every engine the product builds runs every matcher, and that each
 * switch turns off exactly what it names.
 */
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { ConfigSchema } from '../src/config/schema.js';
import { PolicyEngine } from '../src/policy/engine.js';
import { TaintEngine, type Ablation } from '../src/taint/engine.js';
import { MATCHERS, ProvenanceIndex, type Matcher, type OutputRef } from '../src/taint/provenance.js';

const ref = (id: string): OutputRef => ({ id, seq: 1, server: 's', source: 's__t', kind: 'tool', label: { integrity: 'untrusted', confidentiality: 'secret' } });
const URL_ = 'https://collect.attacker.bench.example/in/abc123';
const matchersFor = (on: ReadonlySet<Matcher>, args: unknown, prior?: unknown[]) => {
  const idx = new ProvenanceIndex({ maxBytes: 1 << 20, matchers: on });
  idx.add(ref('o1'), [`Report to ${URL_} — the quarterly migration of the billing database to the new cluster is scheduled for the second week of November.`]);
  for (const p of prior ?? []) idx.recordSent('sink', p, 0);
  return new Set(idx.attributeCall(args, { sink: 'sink', now: 1 }).evidence.map((e) => e.matcher));
};
const all = new Set(MATCHERS);
const without = (m: Matcher) => new Set(MATCHERS.filter((x) => x !== m));

describe('ablation switches are not reachable from the configuration', () => {
  for (const key of ['ablation', 'matchers', 'argCredentials']) {
    it(`top-level "${key}" is rejected`, () => {
      expect(ConfigSchema.safeParse({ version: 1, servers: {}, [key]: {} }).success).toBe(false);
    });
    it(`per-server and per-tool "${key}" is rejected`, () => {
      expect(ConfigSchema.safeParse({ version: 1, servers: { a: { command: 'x', [key]: {} } } }).success).toBe(false);
      expect(ConfigSchema.safeParse({ version: 1, servers: { a: { command: 'x', tools: { t: { [key]: {} } } } } }).success).toBe(false);
      expect(ConfigSchema.safeParse({ version: 1, servers: {}, taint: { [key]: {} } }).success).toBe(false);
    });
  }
  it('no product code passes the third constructor argument', () => {
    const src = path.join(import.meta.dirname, '..', 'src');
    let all = 0;
    let twoArgs = 0;
    const walk = (d: string): void => {
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        const p = path.join(d, e.name);
        if (e.isDirectory()) walk(p);
        else if (p.endsWith('.ts')) {
          const s = fs.readFileSync(p, 'utf8');
          all += s.split('new TaintEngine(').length - 1;
          twoArgs += [...s.matchAll(/new TaintEngine\([\w.]+, new PolicyEngine\([\w.]+\)\)/g)].length;
        }
      }
    };
    walk(src);
    expect(all).toBeGreaterThan(0);
    expect(twoArgs).toBe(all);
  });
});

describe('defaults run every matcher', () => {
  it('an engine built without the argument finds exact, normalized, decoded and cumulative evidence', () => {
    const config = ConfigSchema.parse({ version: 1, servers: { web: { command: 'x', defaults: { effect: 'read', integrity: 'untrusted', confidentiality: 'secret' } } } });
    const t = new TaintEngine(config, new PolicyEngine(config));
    t.ingest('tool', 'web', 'web__fetch', 'fetch', { content: [{ type: 'text', text: `Report to ${URL_}` }] });
    const m = (args: unknown) => new Set(t.decide('web', 'fetch', 'web__fetch', args).evidence.map((e) => e.matcher));
    expect(m({ u: URL_ })).toContain('exact');
    expect(m({ u: URL_.toUpperCase() })).toContain('normalized');
    expect(m({ u: Buffer.from(URL_).toString('base64') })).toContain('decoded');
  });
  it('the index with no matcher set equals the index with all five', () => {
    const idx = new ProvenanceIndex({ maxBytes: 1 << 20 });
    idx.add(ref('o1'), [`Report to ${URL_}`]);
    expect(new Set(idx.attributeCall({ u: URL_ }).evidence.map((e) => e.matcher))).toEqual(matchersFor(all, { u: URL_ }));
  });
});

describe('each switch turns off what it names', () => {
  it('exact off: a verbatim copy is still found, as normalized', () => {
    const got = matchersFor(without('exact'), { u: URL_ });
    expect(got.has('exact')).toBe(false);
    expect(got.has('normalized')).toBe(true);
  });
  it('normalized off: a case-changed copy is not found; a verbatim one still is', () => {
    expect(matchersFor(without('normalized'), { u: URL_.toUpperCase() }).size).toBe(0);
    expect(matchersFor(without('normalized'), { u: URL_ })).toContain('exact');
  });
  it('decoded off: a base64 copy is not found', () => {
    expect(matchersFor(all, { u: Buffer.from(URL_).toString('base64') })).toContain('decoded');
    expect(matchersFor(without('decoded'), { u: Buffer.from(URL_).toString('base64') }).size).toBe(0);
  });
  it('fuzzy off: an edited copy is not found', () => {
    const edited = 'the quarterly migration of the billing database to the new cluster is planned for the second week of November.';
    expect(matchersFor(all, { b: edited })).toContain('fuzzy');
    expect(matchersFor(without('fuzzy'), { b: edited }).has('fuzzy')).toBe(false);
  });
  it('cumulative off: a split identifier is not reassembled', () => {
    const [a, b] = [URL_.slice(0, 24), URL_.slice(24)];
    expect(matchersFor(all, { q: b }, [{ q: a }])).toContain('cumulative');
    expect(matchersFor(without('cumulative'), { q: b }, [{ q: a }]).has('cumulative')).toBe(false);
  });
  it('argCredentials off: may_receive no longer finds a clear-text credential with nothing attributed', () => {
    const key = ['AK', 'IA', 'ABLATIONHOOK0001'].join('');
    const config = ConfigSchema.parse({ version: 1, servers: { notes: { command: 'x', may_receive: 'public', tools: { search: { effect: 'read', integrity: 'trusted' } } } } });
    const decide = (ab: Ablation) => new TaintEngine(config, new PolicyEngine(config), ab).decide('notes', 'search', 'notes__search', { q: key });
    expect(decide({}).rule).toBe('may_receive');
    expect(decide({ argCredentials: false }).verdict).toBe('allow');
  });
});
