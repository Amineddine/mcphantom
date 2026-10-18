/**
 * R7p-3 and R7p-2 (Phase 7 item 5 review; owner decisions 2026-10-17).
 *
 * R7p-3: Tier B used to stop indexing silently at 200,000 entries, outside the byte budget, so an
 * untrusted source that flooded it with random tokens and then forced Tier-A eviction removed all evidence
 * of a recipient, and `from(…, "untrusted")` deny rules returned false (4/5 policy attacks succeeded in the
 * F3 arm of bench:perf). Now Tier B shares the byte budget and evicts oldest first, every eviction marks the
 * session degraded, and a deny-side `from()` with no match in a degraded session fails closed.
 *
 * R7p-2: a decision recorded one evidence entry per earlier output its argument matched (1,000 matches →
 * a 197 KB decision). Now it keeps the strongest few per argument plus a count.
 */
import { describe, expect, it } from 'vitest';
import { ConfigSchema } from '../src/config/schema.js';
import { PolicyEngine } from '../src/policy/engine.js';
import { capEvidence, MAX_EVIDENCE_PER_ARG, TaintEngine } from '../src/taint/engine.js';
import { ProvenanceIndex, TIER_B_ENTRY_BYTES, TIER_B_SOURCE_BYTES, type Evidence, type OutputRef } from '../src/taint/provenance.js';
import { tokens } from '../bench/perf/filler.js';

const ref = (id: string, integrity: 'trusted' | 'untrusted' = 'untrusted'): OutputRef => ({
  id, seq: Number(id.slice(1)), server: 's', source: 's__t', kind: 'tool', label: { integrity, confidentiality: 'internal' },
});
const text = (t: string) => ({ content: [{ type: 'text', text: t }] });
const ATTACKER = 'ops-desk@attacker.bench.example';
const COLLEAGUE = 'j.doe@corp.bench.example';

describe('Tier B shares the byte budget and evicts oldest first (R7p-3)', () => {
  it('charges each entry, and each further output on an entry, against the budget', () => {
    const idx = new ProvenanceIndex({ maxBytes: 64 * 1024 * 1024 });
    const t = tokens(100, 1);
    idx.add(ref('o1'), [t]);
    const { tierBEntries, tierBBytes } = idx.stats;
    expect(tierBEntries).toBeGreaterThanOrEqual(100);
    expect(tierBBytes).toBe(tierBEntries * TIER_B_ENTRY_BYTES);
    idx.add(ref('o2'), [t]);
    expect(idx.stats.tierBEntries).toBe(tierBEntries);
    expect(idx.stats.tierBBytes).toBe(tierBEntries * (TIER_B_ENTRY_BYTES + TIER_B_SOURCE_BYTES));
  });

  it('never holds more than the budget, Tier A and Tier B together, under an identifier flood', () => {
    const max = 256 * 1024;
    const idx = new ProvenanceIndex({ maxBytes: max });
    for (let i = 1; i <= 20; i++) {
      idx.add(ref(`o${String(i)}`), [tokens(1000, i)]);
      expect(idx.stats.tierABytes + idx.stats.tierBBytes).toBeLessThanOrEqual(max);
    }
    expect(idx.stats.tierBEvicted).toBeGreaterThan(0);
  });

  it('evicts the oldest entries first; an identifier seen again in a newer output counts as new', () => {
    // Entry counts per output, measured on an unbounded index.
    const probe = new ProvenanceIndex({ maxBytes: 1e9 });
    probe.add(ref('o1'), [`Contact: ${ATTACKER}`]);
    const eA = probe.stats.tierBEntries;
    probe.add(ref('o2'), [`Contact: ${COLLEAGUE}`]);
    const eB = probe.stats.tierBEntries - eA;
    const flood = tokens(200, 2);
    probe.add(ref('o4'), [flood]);
    const eF = probe.stats.tierBEntries - eA - eB;

    // Room for A (with its second source) and the flood, not for B: B is the oldest once A is seen again.
    const idx = new ProvenanceIndex({ maxBytes: TIER_B_ENTRY_BYTES * (eA + eF) + TIER_B_SOURCE_BYTES * eA });
    idx.add(ref('o1'), [`Contact: ${ATTACKER}`]);
    idx.add(ref('o2'), [`Contact: ${COLLEAGUE}`]);
    idx.add(ref('o3'), [`Reminder: ${ATTACKER}`]);
    const { evictions } = idx.add(ref('o4'), [flood]);

    expect(evictions.filter((e) => e.tier === 'B')).toEqual([expect.objectContaining({ tier: 'B', output: expect.objectContaining({ id: 'o2' }), entries: eB })]);
    expect(idx.attribute({ to: COLLEAGUE })).toEqual([]);
    expect(idx.attribute({ to: ATTACKER }).map((e) => e.output.id).sort()).toEqual(['o1', 'o3']);
    expect(idx.stats.tierAOutputs).toBe(0);
  });
});

// ---- engine + policy -------------------------------------------------------------------------------------

const config = (rules: { deny?: string; ask?: string; allow?: string }[], extra: Record<string, unknown> = {}) => ConfigSchema.parse({
  version: 1,
  taint: { max_index_mb: 0.0625 },
  servers: {
    web: { command: 'x', tools: { fetch_page: { effect: 'read', integrity: 'untrusted' } } },
    crm: { command: 'x', tools: { notes: { effect: 'read', integrity: 'trusted', confidentiality: 'internal' } } },
    directory: { command: 'x', tools: { lookup: { effect: 'read', integrity: 'trusted', confidentiality: 'public' } } },
    mail: { command: 'x', tools: { send_email: { effect: 'egress', integrity: 'trusted', rules } } },
  },
  ...extra,
});

function engine(rules: { deny?: string; ask?: string; allow?: string }[]) {
  const c = config(rules);
  return new TaintEngine(c, new PolicyEngine(c));
}
const page = (e: TaintEngine, t: string) => e.ingest('tool', 'web', 'web__fetch_page', 'fetch_page', text(t));
/** Enough random tokens from the untrusted source to overflow a 64 KiB index, Tier A and Tier B. */
const floodFrom = (e: TaintEngine) => page(e, tokens(1000, 9));
const send = (e: TaintEngine, to: string, subject = 'notes') => e.decide('mail', 'send_email', 'mail__send_email', { to, subject, body: 'Renewal notes attached.' });

describe('deny-side from() fails closed in a degraded session (R7p-3)', () => {
  const RULE = [{ deny: 'from(arg.to, "untrusted")' }];

  it('the flood after the recipient no longer hides it: the deny fails closed, naming the bound and the way out', () => {
    const e = engine(RULE);
    page(e, `Page text. [[UNTRUSTED_PLACEHOLDER]] Contact: ${ATTACKER}`);
    e.ingest('tool', 'crm', 'crm__notes', 'notes', text('Account notes (internal).'));
    const lost = floodFrom(e);
    expect(lost.evictions.some((x) => x.tier === 'B')).toBe(true);
    const d = send(e, ATTACKER);
    expect(d).toMatchObject({ verdict: 'deny', rule: 'policy', attributionDegraded: true });
    expect(d.evidence).toEqual([]);
    expect(d.reason).toContain('fail-closed');
    expect(d.reason).toContain('untrusted outputs');
    expect(d.reason).toContain('taint.max_index_mb');
  });

  it('a flood before the recipient: the recipient is the newest entry, so the rule denies on evidence', () => {
    const e = engine(RULE);
    floodFrom(e);
    page(e, `Page text. [[UNTRUSTED_PLACEHOLDER]] Contact: ${ATTACKER}`);
    const d = send(e, ATTACKER);
    expect(d.verdict).toBe('deny');
    expect(d.reason).not.toContain('fail-closed');
    expect(d.evidence.length).toBeGreaterThan(0);
  });

  it('the cost: a benign recipient from a trusted source is denied once untrusted outputs were lost', () => {
    const fresh = engine(RULE);
    page(fresh, 'Ordinary page.');
    fresh.ingest('tool', 'directory', 'directory__lookup', 'lookup', text(`Owner: ${COLLEAGUE}`));
    expect(send(fresh, COLLEAGUE).verdict).toBe('allow');

    const e = engine(RULE);
    floodFrom(e);
    e.ingest('tool', 'directory', 'directory__lookup', 'lookup', text(`Owner: ${COLLEAGUE}`));
    const d = send(e, COLLEAGUE);
    expect(d.verdict).toBe('deny');
    expect(d.reason).toContain('fail-closed');
  });

  it('a negated from() fails closed too (an error, not true), and so does an ask rule', () => {
    for (const rule of [{ deny: '!from(arg.to, "untrusted")' }, { ask: 'from(arg.to, "untrusted")' }]) {
      const e = engine([rule]);
      floodFrom(e);
      const d = send(e, COLLEAGUE);
      expect(d.verdict).toBe('deny');
      expect(d.reason).toContain('fail-closed');
    }
  });

  it('a rule that cannot match anyway stays unmatched (CEL: false && error is false)', () => {
    const e = engine([{ deny: 'from(arg.to, "untrusted") && arg.subject == "never sent"' }]);
    floodFrom(e);
    expect(send(e, COLLEAGUE).verdict).toBe('allow');
  });

  it('only the lost level is unsure: from(…, "trusted") still trusts a missing match when only untrusted outputs were lost', () => {
    const e = engine([{ deny: 'from(arg.to, "trusted")' }]);
    floodFrom(e);
    expect(send(e, ATTACKER).verdict).toBe('allow');
  });

  it('a value attribution cannot check in full (> 64 KiB) fails closed, with no eviction at all', () => {
    const c = config(RULE);
    c.taint.max_index_mb = 32;
    const e = new TaintEngine(c, new PolicyEngine(c));
    page(e, 'Ordinary page.');
    const d = send(e, 'a '.repeat(36 * 1024));
    expect(d.verdict).toBe('deny');
    expect(d.reason).toContain('could not check this value in full');
  });

  it('allow rules and declassify conditions are unchanged: no error, a missing match is simply false', () => {
    const c = config([{ allow: 'from(arg.to, "untrusted")' }]);
    const p = new PolicyEngine(c);
    const inputs = {
      serverId: 'mail', toolName: 'send_email', args: { to: COLLEAGUE, subject: 's', body: 'b' },
      context: { integrity: 'untrusted', confidentiality: 'internal' }, provenanceOf: () => new Set<'trusted' | 'untrusted'>(), unsure: () => 'lost track',
    } as const;
    const o = p.evaluate(inputs);
    expect(o.errors).toEqual([]);
    expect(o.effect).toBeUndefined();

    const d = new PolicyEngine(config([], { declassify: [{ id: 'dir', tool: 'mail__send_email', when: 'from(arg.to, "trusted")', reason: 'directory' }] })).evaluate(inputs);
    expect(d.errors).toEqual([]);
    expect(d.declassified).toBeUndefined();
  });
});

describe('decision evidence is capped per argument (R7p-2)', () => {
  it('1,000 matching outputs give the strongest few entries and a count, not 1,000 entries', () => {
    const c = config([]);
    c.taint.max_index_mb = 32;
    const e = new TaintEngine(c, new PolicyEngine(c));
    const phrase = 'quarterly renewal summary for the account team';
    for (let i = 0; i < 1000; i++) page(e, `Page ${String(i)}: ${phrase}.`);
    const d = e.decide('mail', 'send_email', 'mail__send_email', { to: COLLEAGUE, subject: phrase, body: 'b' });
    expect(d.evidence.length).toBeLessThanOrEqual(MAX_EVIDENCE_PER_ARG);
    expect(d.evidence.length + (d.evidenceOmitted ?? 0)).toBeGreaterThanOrEqual(1000);
    // The newest outputs are kept among equals.
    expect(Math.min(...d.evidence.map((x) => x.output.seq))).toBeGreaterThan(990);
    expect(JSON.stringify(d).length).toBeLessThan(8 * 1024);
  });

  it('keeps the strongest entries, and always the one a deny cites, in attribution order', () => {
    const out = (seq: number, conf: 'public' | 'internal' | 'secret', integrity: 'trusted' | 'untrusted' = 'trusted'): OutputRef =>
      ({ id: `o${String(seq)}`, seq, server: 's', source: `s__t${String(seq)}`, kind: 'tool', label: { integrity, confidentiality: conf } });
    const ev = (seq: number, conf: 'public' | 'internal' | 'secret', matcher: Evidence['matcher'], integrity: 'trusted' | 'untrusted' = 'trusted', argPath = '$.body'): Evidence =>
      ({ argPath, output: out(seq, conf, integrity), kind: 'copy', matcher });
    const pinned = ev(1, 'public', 'cumulative');
    const all = [pinned, ...Array.from({ length: 10 }, (_, i) => ev(i + 2, 'public', 'exact')), ev(20, 'secret', 'fuzzy'), ev(21, 'internal', 'exact', 'untrusted'), ev(22, 'public', 'exact', 'trusted', '$.to')];
    const { kept, omitted } = capEvidence(all, pinned);
    expect(kept.map((e) => e.output.seq)).toEqual([1, 11, 20, 21, 22]);
    expect(omitted).toBe(all.length - kept.length);
    expect(capEvidence(all).kept.map((e) => e.output.seq)).toEqual([10, 11, 20, 21, 22]);
  });
});
