/**
 * Tier-1 benchmark for the entropy-based "possible secret" detector (src/secrets/entropy.ts).
 * Deterministic, no model, runs in CI.
 *
 *   npm run bench:entropy            # full report + CI floor (test split)
 *   npm run bench:entropy -- --dev   # dev split only: the only view used while tuning
 *
 * False positives: benign tool outputs, real (this repository, its public GitHub metadata, npm
 * registry metadata) and synthetic (bench/corpus/build-benign-outputs.mjs: cloud, kubectl, docker,
 * payment, tracing, analytics and document-store outputs full of random-looking identifiers). A
 * `random` hit on a benign output is a false positive; `hash` hits are reported separately (they are
 * redacted but never escalate).
 *
 * Detection: random secrets with no known format and no keyword, generated from a seeded PRNG at run
 * time (so no secret-shaped string is committed), embedded in neutral contexts. Hex-encoded secrets
 * are classified `hash` by design and are reported as a published miss, not hidden.
 *
 * Splits: every item's split is a stable hash of its id, fixed before any tuning. The detector was
 * tuned on `dev` only; `test` is the held-out number.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { findSecrets } from '../src/secrets/detectors.js';
import { findPossibleSecrets, type EntropyShape } from '../src/secrets/entropy.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const devOnly = process.argv.includes('--dev');

type Split = 'dev' | 'test';
const stableSplit = (key: string): Split => (parseInt(crypto.createHash('sha256').update(`entropy|${key}`).digest('hex')[0] ?? '0', 16) % 2 === 0 ? 'test' : 'dev');

interface Benign { id: string; group: string; split: Split; text: string }
function loadBenign(): Benign[] {
  const real = JSON.parse(fs.readFileSync(path.join(here, 'corpus', 'benign-outputs-real.json'), 'utf8')) as { items: { id: string; text: string }[] };
  const syn = JSON.parse(fs.readFileSync(path.join(here, 'corpus', 'benign-outputs-synthetic.json'), 'utf8')) as { items: { id: string; template: string; text: string }[] };
  return [
    ...real.items.map((i) => ({ id: `real:${i.id}`, group: 'real', split: stableSplit(`real:${i.id}`), text: i.text })),
    ...syn.items.map((i) => ({ id: `syn:${i.id}`, group: `synthetic:${i.template}`, split: stableSplit(`syn:${i.id}`), text: i.text })),
  ];
}

// --- positives -------------------------------------------------------------------------------
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
const ALPHA = {
  base62: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
  base57: 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789',
  base64: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
  base64url: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
  base36: 'abcdefghijklmnopqrstuvwxyz0123456789',
  hex: '0123456789abcdef',
} as const;
type Alpha = keyof typeof ALPHA;
interface Kind { alpha: Alpha; len: number; expect: EntropyShape }
const kinds = (alpha: Alpha, expect: EntropyShape, lens: number[]): Kind[] => lens.map((len) => ({ alpha, len, expect }));
const KINDS: Kind[] = [
  ...kinds('base62', 'random', [20, 24, 32, 40, 48, 64]),
  ...kinds('base57', 'random', [44, 48]),
  ...kinds('base64', 'random', [24, 44, 88]),
  ...kinds('base64url', 'random', [22, 43, 64]),
  ...kinds('base36', 'random', [25, 32]),
  ...kinds('hex', 'hash', [32, 40, 64]),
];
// Neutral contexts: no keyword a known-format rule would key on (no "token", "key", "secret", "password").
const CONTEXTS = [
  (t: string) => `Created. Copy this value now, it will not be shown again:\n\n${t}\n`,
  (t: string) => JSON.stringify({ id: 42, name: 'ci-deploy', value: t, created: '2026-10-01' }),
  (t: string) => `export DEPLOY_CREDENTIAL_VALUE=${t}`,
  (t: string) => `| ci-deploy | ${t} | 2026-10-01 |`,
  (t: string) => `connect with --auth ${t} to continue`,
];

interface Positive { id: string; kind: string; expect: EntropyShape; split: Split; text: string; value: string }
function positives(): Positive[] {
  const out: Positive[] = [];
  let seed = 7_000;
  for (const k of KINDS) {
    for (let i = 0; i < 8; i++) {
      const r = rng(seed++);
      const a = ALPHA[k.alpha];
      let v = Array.from({ length: k.len }, () => a[Math.floor(r() * a.length)]).join('');
      if (k.alpha === 'base64' && k.len % 4 === 0) v = v.slice(0, -1) + '=';
      const ctx = CONTEXTS[i % CONTEXTS.length] as (t: string) => string;
      const id = `${k.alpha}-${k.len}-${i}`;
      out.push({ id, kind: `${k.alpha}/${k.len}`, expect: k.expect, split: stableSplit(`pos:${id}`), text: ctx(v), value: v });
    }
  }
  return out;
}

// --- scoring ---------------------------------------------------------------------------------
function hits(text: string): { random: string[]; hash: number } {
  const known = findSecrets(text);
  const inKnown = (s: number, e: number) => known.some((k) => s < k.end && e > k.start);
  const random: string[] = [];
  let hash = 0;
  for (const p of findPossibleSecrets(text)) {
    if (inKnown(p.start, p.end)) continue;
    if (p.shape === 'random') random.push(text.slice(p.start, p.end));
    else hash++;
  }
  return { random, hash };
}

interface SplitReport {
  benign: { outputs: number; flagged: number; randomHits: number; hashHits: number; fprOutputs: number; examples: string[]; byGroup: Record<string, { outputs: number; flagged: number }> };
  positives: { total: number; detected: number; tpr: number; byKind: Record<string, { total: number; random: number; hash: number; missed: number }> };
}

function evaluate(split: Split | 'all', benign: Benign[], pos: Positive[]): SplitReport {
  const b = benign.filter((x) => split === 'all' || x.split === split);
  const p = pos.filter((x) => split === 'all' || x.split === split);
  const byGroup: SplitReport['benign']['byGroup'] = {};
  let flagged = 0, randomHits = 0, hashHits = 0;
  const examples: string[] = [];
  for (const item of b) {
    const g = (byGroup[item.group] ??= { outputs: 0, flagged: 0 });
    g.outputs++;
    const h = hits(item.text);
    randomHits += h.random.length;
    hashHits += h.hash;
    if (h.random.length) {
      flagged++;
      g.flagged++;
      for (const v of h.random.slice(0, 2)) examples.push(`${item.id}: ${v.length > 48 ? v.slice(0, 48) + '…' : v}`);
    }
  }
  const byKind: SplitReport['positives']['byKind'] = {};
  let detected = 0;
  const expectRandom = p.filter((x) => x.expect === 'random');
  for (const item of p) {
    const k = (byKind[item.kind] ??= { total: 0, random: 0, hash: 0, missed: 0 });
    k.total++;
    const found = findPossibleSecrets(item.text).find((x) => item.text.slice(x.start, x.end).includes(item.value) || item.value.includes(item.text.slice(x.start, x.end)));
    if (!found) k.missed++;
    else if (found.shape === 'random') k.random++;
    else k.hash++;
    if (item.expect === 'random' && found?.shape === 'random') detected++;
  }
  return {
    benign: { outputs: b.length, flagged, randomHits, hashHits, fprOutputs: b.length ? flagged / b.length : 0, examples, byGroup },
    positives: { total: expectRandom.length, detected, tpr: expectRandom.length ? detected / expectRandom.length : 0, byKind },
  };
}

const log = (line: string): void => {
  process.stdout.write(line + '\n');
};
const pct = (x: number) => `${(100 * x).toFixed(1)}%`;
function print(name: string, r: SplitReport): void {
  log(`\n== ${name} ==`);
  log(`benign outputs: ${r.benign.outputs}, flagged (any random hit): ${r.benign.flagged} → FPR ${pct(r.benign.fprOutputs)}; random hits ${r.benign.randomHits}, hash-shaped hits ${r.benign.hashHits}`);
  log(`random-secret detection: ${r.positives.detected}/${r.positives.total} → ${pct(r.positives.tpr)}`);
  for (const [k, v] of Object.entries(r.positives.byKind)) log(`  ${k.padEnd(14)} random ${v.random}/${v.total}  hash ${v.hash}  missed ${v.missed}`);
  const noisy = Object.entries(r.benign.byGroup).filter(([, v]) => v.flagged > 0);
  if (noisy.length) log(`flagged groups: ${noisy.map(([g, v]) => `${g} ${v.flagged}/${v.outputs}`).join(', ')}`);
  for (const e of r.benign.examples.slice(0, 40)) log(`  FP ${e}`);
}

const benign = loadBenign();
const pos = positives();
const dev = evaluate('dev', benign, pos);
print('dev split (tuning)', dev);
if (devOnly) process.exit(0);

const test = evaluate('test', benign, pos);
const all = evaluate('all', benign, pos);
print('test split (held out)', test);
print('all', all);

// CI floor on the held-out split, set from the first frozen run with headroom (docs/reviews/phase-6b.md).
const FLOOR = { maxFprOutputs: 0.5, minTpr: 0.95 }; // first frozen run: test FPR 40.0%, detection 100%
const resultsDir = path.join(here, 'results');
fs.mkdirSync(resultsDir, { recursive: true });
const md = [
  '# Entropy detector benchmark (`npm run bench:entropy`)',
  '',
  `Node ${process.version}, ${os.platform()} ${os.arch()}. Deterministic; corpus and seeds in the repository.`,
  '',
  '| split | benign outputs | flagged (FPR) | random hits | hash-shaped hits | random-secret detection |',
  '|---|---|---|---|---|---|',
  ...([['dev', dev], ['test (held out)', test], ['all', all]] as const).map(([n, r]) => `| ${n} | ${r.benign.outputs} | ${r.benign.flagged} (${pct(r.benign.fprOutputs)}) | ${r.benign.randomHits} | ${r.benign.hashHits} | ${r.positives.detected}/${r.positives.total} (${pct(r.positives.tpr)}) |`),
  '',
  '## Detection by kind (all splits)',
  '',
  '| kind | classified random | classified hash | missed |',
  '|---|---|---|---|',
  ...Object.entries(all.positives.byKind).map(([k, v]) => `| ${k} | ${v.random}/${v.total} | ${v.hash} | ${v.missed} |`),
  '',
  'Hex values are classified `hash` by design (digests and ids are hex), so a hex-encoded secret is a published miss of this detector.',
  '',
  '## Benign outputs with a random hit (all splits)',
  '',
  '| group | flagged / outputs |',
  '|---|---|',
  ...Object.entries(all.benign.byGroup).filter(([, v]) => v.flagged).map(([g, v]) => `| ${g} | ${v.flagged}/${v.outputs} |`),
  '',
  `CI floor (test split): FPR ≤ ${pct(FLOOR.maxFprOutputs)}, detection ≥ ${pct(FLOOR.minTpr)}.`,
  '',
];
fs.writeFileSync(path.join(resultsDir, 'entropy-bench.md'), md.join('\n'));
if (test.benign.fprOutputs > FLOOR.maxFprOutputs || test.positives.tpr < FLOOR.minTpr) {
  console.error(`\nFAIL: held-out split below the floor (FPR ${pct(test.benign.fprOutputs)} > ${pct(FLOOR.maxFprOutputs)} or detection ${pct(test.positives.tpr)} < ${pct(FLOOR.minTpr)})`);
  process.exit(1);
}
log('\nOK: held-out split within the floor');
