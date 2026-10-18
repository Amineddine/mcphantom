/**
 * Layer-2 `fuzzy` matcher: winnowing fingerprints over normalized letters/digits.
 */
import { describe, expect, it } from 'vitest';
import { containment, fingerprints, K, reduce, W } from '../src/taint/fuzzy.js';
import { ProvenanceIndex, type OutputRef } from '../src/taint/provenance.js';

const ref = (id: string): OutputRef => ({ id, seq: Number(id.slice(1)), server: 'web', source: 'web__fetch', kind: 'tool', label: { integrity: 'untrusted', confidentiality: 'public' } });

function rng(seed: number): () => number {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const randomText = (r: () => number, n: number) => Array.from({ length: n }, () => 'abcdefghijklmnopqrstuvwxyz0123456789'[Math.floor(r() * 36)]).join('');

const SOURCE = [
  'Quarterly planning notes for the infrastructure group.',
  'The migration of the billing database to the new cluster is scheduled for the second week of November.',
  'Rollback requires the snapshot taken the night before and approval from the on-call lead.',
  'Customer-facing downtime must stay under fifteen minutes, measured from the first failed health check.',
].join(' ');

describe('winnowing fingerprints', () => {
  it('guarantee: any shared run of W + K - 1 reduced characters yields a shared fingerprint (property, 300 cases)', () => {
    const r = rng(7);
    for (let i = 0; i < 300; i++) {
      const shared = randomText(r, W + K - 1);
      const a = fingerprints(randomText(r, 50 + Math.floor(r() * 200)) + shared + randomText(r, Math.floor(r() * 200)));
      const b = fingerprints(randomText(r, Math.floor(r() * 200)) + shared + randomText(r, 50));
      expect(containment(fingerprints(shared), a).shared).toBeGreaterThan(0);
      expect(containment(a, b).shared).toBeGreaterThan(0);
    }
  });

  it('ignores whitespace, punctuation, case and look-alikes', () => {
    expect(reduce('Hello, Wоrld!  2026')).toBe('helloworld2026'); // Cyrillic о
    expect(containment(fingerprints(SOURCE.toUpperCase().replace(/ /g, '\n')), fingerprints(SOURCE)).score).toBe(1);
  });

  it('is cheap on 1 MB', () => {
    const t0 = performance.now();
    fingerprints(randomText(rng(1), 1 << 20));
    expect(performance.now() - t0).toBeLessThan(2000);
  });
});

describe('ProvenanceIndex: fuzzy matcher', () => {
  it('attributes text copied with light edits', () => {
    const idx = new ProvenanceIndex({ maxBytes: 1e7 });
    idx.add(ref('o1'), [SOURCE]);
    const edited = SOURCE.replace('scheduled for', 'planned for').replace('approval from', 'sign-off by').replace('fifteen', '15');
    const ev = idx.attribute({ body: edited });
    expect(ev).toEqual([expect.objectContaining({ kind: 'copy', matcher: 'fuzzy', output: expect.objectContaining({ id: 'o1' }) })]);
    expect(ev[0]?.score).toBeGreaterThanOrEqual(0.5);
  });

  it('attributes reordered sentences', () => {
    const idx = new ProvenanceIndex({ maxBytes: 1e7 });
    idx.add(ref('o1'), [SOURCE]);
    const reordered = SOURCE.split('. ').reverse().join('. ');
    expect(idx.attribute({ body: reordered })[0]).toMatchObject({ matcher: 'fuzzy' });
  });

  it('a verbatim copy is reported once, as exact, not again as fuzzy', () => {
    const idx = new ProvenanceIndex({ maxBytes: 1e7 });
    idx.add(ref('o1'), [SOURCE]);
    expect(idx.attribute({ body: SOURCE.slice(60, 220) })).toEqual([expect.objectContaining({ matcher: 'exact' })]);
  });

  it('does not match unrelated text that shares common phrases', () => {
    const idx = new ProvenanceIndex({ maxBytes: 1e7 });
    idx.add(ref('o1'), [SOURCE]);
    const unrelated = 'Notes for the second week of the quarter: the team will review the new onboarding guide and the hiring plan before the offsite.';
    expect(idx.attribute({ body: unrelated })).toEqual([]);
  });

  it('a short value is not fuzzy-compared at all', () => {
    const idx = new ProvenanceIndex({ maxBytes: 1e7 });
    idx.add(ref('o1'), [SOURCE]);
    expect(idx.attribute({ body: 'billing database cluster' })).toEqual([]);
  });

  it('heavy rewording (paraphrase) is not attributed — the documented limit; Layer 1 still applies', () => {
    const idx = new ProvenanceIndex({ maxBytes: 1e7 });
    idx.add(ref('o1'), [SOURCE]);
    const paraphrase = 'Infra team plan: in mid-November we move billing onto the fresh cluster; to undo it you need last night\'s snapshot and an OK from whoever is on call; customers may see at most a quarter hour of outage.';
    expect(idx.attribute({ body: paraphrase })).toEqual([]);
  });

  it('fingerprints count against the Tier-A budget', () => {
    const idx = new ProvenanceIndex({ maxBytes: 1e7 });
    idx.add(ref('o1'), [SOURCE]);
    expect(idx.stats.tierABytes).toBeGreaterThan(SOURCE.length * 2);
  });

  // 6a review, untested path 5: fingerprints live in Tier A and leave with it. The loss must be
  // reported (eviction notice → `attribution_degraded` in the engine), never silent.
  it('a fuzzy match disappears once its output is evicted from Tier A, and the eviction is reported', () => {
    const probe = new ProvenanceIndex({ maxBytes: 1e7 });
    probe.add(ref('o1'), [SOURCE]);
    const oneEntry = probe.stats.tierABytes;
    const edited = SOURCE.replace('scheduled for', 'planned for').replace('approval from', 'sign-off by');
    const filler = randomText(rng(7), SOURCE.length);
    probe.add(ref('o2'), [filler]);
    // Tier B shares the budget (R7p-3); leave room for both outputs' identifiers so only Tier A evicts.
    const budget = Math.ceil(oneEntry * 1.5) + probe.stats.tierBBytes;

    const idx = new ProvenanceIndex({ maxBytes: budget });
    idx.add(ref('o1'), [SOURCE]);
    expect(idx.attribute({ body: edited })[0]).toMatchObject({ matcher: 'fuzzy', output: expect.objectContaining({ id: 'o1' }) });

    const { evictions } = idx.add(ref('o2'), [filler]);
    expect(evictions.map((e) => `${e.tier}:${e.output.id}`)).toEqual(['A:o1']);
    expect(idx.stats.tierABytes).toBeLessThanOrEqual(Math.ceil(oneEntry * 1.5));
    expect(idx.attribute({ body: edited }).filter((e) => e.matcher === 'fuzzy')).toEqual([]);
  });

  it('stays fast against a large index (400 outputs of 8 KB, an 8 KB argument)', () => {
    const r = rng(3);
    const idx = new ProvenanceIndex({ maxBytes: 1e9 });
    for (let i = 0; i < 400; i++) idx.add(ref(`o${i + 1}`), [randomText(r, 8192)]);
    const t0 = performance.now();
    idx.attribute({ body: randomText(r, 8192) });
    expect(performance.now() - t0).toBeLessThan(3000);
  });
});
