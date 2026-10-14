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
 * `random` hit on a benign output is a false positive; identifier-shaped (`id`) hits are reported
 * separately (they are redacted but never escalate).
 *
 * Detection: random secrets with no known format and no keyword, generated from a seeded PRNG at run
 * time (so no secret-shaped string is committed), embedded in neutral contexts. Detection = classified
 * `random` (only those can escalate), over EVERY generated secret, including the kinds the detector
 * misses by design (hex, an unknown vendor's prefixed key, a secret under an id-named field), so the
 * cost of each design choice is in the number, not beside it.
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
import { findPossibleSecrets } from '../src/secrets/entropy.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const devOnly = process.argv.includes('--dev');

type Split = 'dev' | 'test';
const stableSplit = (key: string): Split => (parseInt(crypto.createHash('sha256').update(`entropy|${key}`).digest('hex')[0] ?? '0', 16) % 2 === 0 ? 'test' : 'dev');

interface Benign { id: string; group: string; split: Split; text: string }
function loadBenign(): Benign[] {
  const real = JSON.parse(fs.readFileSync(path.join(here, 'corpus', 'benign-outputs-real.json'), 'utf8')) as { items: { id: string; text: string }[] };
  const syn = JSON.parse(fs.readFileSync(path.join(here, 'corpus', 'benign-outputs-synthetic.json'), 'utf8')) as { items: { id: string; template: string; text: string }[] };
  return [
    ...real.items.map((i) => ({ id: `real:${i.id}`, group: `real:${i.id.replace(/-.*$/, '')}`, split: stableSplit(`real:${i.id}`), text: i.text })),
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
interface Kind { name: string; alpha: Alpha; len: number; prefix?: string; ctx?: (t: string) => string }
const kinds = (alpha: Alpha, lens: number[]): Kind[] => lens.map((len) => ({ name: `${alpha}/${len}`, alpha, len }));
const KINDS: Kind[] = [
  ...kinds('base62', [20, 24, 32, 40, 48, 64]),
  ...kinds('base57', [44, 48]),
  ...kinds('base64', [24, 44, 88]),
  ...kinds('base64url', [22, 43, 64]),
  ...kinds('base36', [25, 32]),
  // Misses by design, measured so their cost is visible:
  ...kinds('hex', [32, 40, 64]),
  { name: 'unknown-vendor prefix zq_/40', alpha: 'base62', len: 40, prefix: 'zq_' },
  { name: 'under an "id" field/40', alpha: 'base62', len: 40, ctx: (t) => JSON.stringify({ id: t, name: 'ci-deploy' }) },
  // ...and the guard that keeps a credential-named id field a possible secret:
  { name: 'under "secret_id"/40', alpha: 'base62', len: 40, ctx: (t) => JSON.stringify({ role_id: 'ci', secret_id: t }) },
];
// Neutral contexts: no keyword a known-format rule would key on (no "token", "key", "secret", "password").
const CONTEXTS = [
  (t: string) => `Created. Copy this value now, it will not be shown again:\n\n${t}\n`,
  (t: string) => JSON.stringify({ id: 42, name: 'ci-deploy', value: t, created: '2026-10-01' }),
  (t: string) => `export DEPLOY_CREDENTIAL_VALUE=${t}`,
  (t: string) => `| ci-deploy | ${t} | 2026-10-01 |`,
  (t: string) => `connect with --auth ${t} to continue`,
];

interface Positive { id: string; kind: string; split: Split; text: string; value: string }
function positives(): Positive[] {
  const out: Positive[] = [];
  let seed = 7_000;
  for (const k of KINDS) {
    for (let i = 0; i < 8; i++) {
      const r = rng(seed++);
      const a = ALPHA[k.alpha];
      let v = Array.from({ length: k.len }, () => a[Math.floor(r() * a.length)]).join('');
      if (k.alpha === 'base64' && k.len % 4 === 0) v = v.slice(0, -1) + '=';
      v = (k.prefix ?? '') + v;
      const ctx = k.ctx ?? CONTEXTS[i % CONTEXTS.length] ?? ((t: string) => t);
      // Original kinds keep their original ids (and so their splits); new kinds get a named id.
      const id = k.prefix || k.ctx ? `${k.name}-${i}` : `${k.alpha}-${k.len}-${i}`;
      out.push({ id, kind: k.name, split: stableSplit(`pos:${id}`), text: ctx(v), value: v });
    }
  }
  return out;
}

// --- scoring ---------------------------------------------------------------------------------
/** Token-shape taxonomy for the false-positive breakdown (descriptive only; not used by the detector). */
export function tokenShape(t: string): string {
  const len = t.length <= 24 ? '20-24' : t.length <= 32 ? '25-32' : t.length <= 48 ? '33-48' : '49+';
  let cls: string;
  if (/^[A-Za-z]{1,8}_[A-Za-z0-9]/.test(t)) cls = 'type-prefixed (word_...)';
  else if (/^[a-z0-9]+$/.test(t)) cls = 'lowercase+digits (base36)';
  else if (/^[A-Z0-9]+$/.test(t)) cls = 'uppercase+digits';
  else if (/[+/]|=$/.test(t)) cls = 'base64 (+ / =)';
  else if (/[-_]/.test(t)) cls = 'base64url (- _)';
  else cls = 'mixed-case alnum (base62)';
  return `${cls} ${len}`;
}

function hits(text: string): { random: string[]; id: number } {
  const known = findSecrets(text);
  const inKnown = (s: number, e: number) => known.some((k) => s < k.end && e > k.start);
  const random: string[] = [];
  let id = 0;
  for (const p of findPossibleSecrets(text)) {
    if (inKnown(p.start, p.end)) continue;
    if (p.shape === 'random') random.push(text.slice(p.start, p.end));
    else id++;
  }
  return { random, id };
}

interface SplitReport {
  benign: { outputs: number; flagged: number; randomHits: number; idHits: number; fprOutputs: number; examples: string[]; byGroup: Record<string, { outputs: number; flagged: number }>; byShape: Record<string, { hits: number; outputs: Set<string> }> };
  positives: { total: number; detected: number; tpr: number; byKind: Record<string, { total: number; random: number; id: number; missed: number }> };
}

function evaluate(split: Split | 'all', benign: Benign[], pos: Positive[]): SplitReport {
  const b = benign.filter((x) => split === 'all' || x.split === split);
  const p = pos.filter((x) => split === 'all' || x.split === split);
  const byGroup: SplitReport['benign']['byGroup'] = {};
  const byShape: SplitReport['benign']['byShape'] = {};
  let flagged = 0, randomHits = 0, idHits = 0;
  const examples: string[] = [];
  for (const item of b) {
    const g = (byGroup[item.group] ??= { outputs: 0, flagged: 0 });
    g.outputs++;
    const h = hits(item.text);
    randomHits += h.random.length;
    idHits += h.id;
    for (const v of h.random) {
      const sh = (byShape[tokenShape(v)] ??= { hits: 0, outputs: new Set() });
      sh.hits++;
      sh.outputs.add(item.id);
    }
    if (h.random.length) {
      flagged++;
      g.flagged++;
      for (const v of h.random.slice(0, 2)) examples.push(`${item.id}: ${v.length > 48 ? v.slice(0, 48) + '…' : v}`);
    }
  }
  const byKind: SplitReport['positives']['byKind'] = {};
  let detected = 0;
  for (const item of p) {
    const k = (byKind[item.kind] ??= { total: 0, random: 0, id: 0, missed: 0 });
    k.total++;
    const found = findPossibleSecrets(item.text).find((x) => item.text.slice(x.start, x.end).includes(item.value) || item.value.includes(item.text.slice(x.start, x.end)));
    if (!found) k.missed++;
    else if (found.shape === 'random') k.random++;
    else k.id++;
    if (found?.shape === 'random') detected++;
  }
  return {
    benign: { outputs: b.length, flagged, randomHits, idHits, fprOutputs: b.length ? flagged / b.length : 0, examples, byGroup, byShape },
    positives: { total: p.length, detected, tpr: p.length ? detected / p.length : 0, byKind },
  };
}

const log = (line: string): void => {
  process.stdout.write(line + '\n');
};
const pct = (x: number) => `${(100 * x).toFixed(1)}%`;
function print(name: string, r: SplitReport): void {
  log(`\n== ${name} ==`);
  log(`benign outputs: ${r.benign.outputs}, flagged (any random hit): ${r.benign.flagged} → FPR ${pct(r.benign.fprOutputs)}; random hits ${r.benign.randomHits}, id-shaped hits ${r.benign.idHits}`);
  log(`detection (classified random, all generated secrets): ${r.positives.detected}/${r.positives.total} → ${pct(r.positives.tpr)}`);
  for (const [k, v] of Object.entries(r.positives.byKind)) log(`  ${k.padEnd(30)} random ${v.random}/${v.total}  id ${v.id}  missed ${v.missed}`);
  const noisy = Object.entries(r.benign.byGroup).filter(([, v]) => v.flagged > 0);
  if (noisy.length) log(`flagged groups: ${noisy.map(([g, v]) => `${g} ${v.flagged}/${v.outputs}`).join(', ')}`);
  log('false positives by token shape (hits / outputs):');
  for (const [k, v] of Object.entries(r.benign.byShape).sort((a, b) => b[1].outputs.size - a[1].outputs.size)) log(`  ${k.padEnd(40)} ${String(v.hits).padStart(4)} / ${v.outputs.size}`);
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

// CI floor on the held-out split, set from the tuned frozen run with headroom (docs/reviews/phase-6b.md).
const FLOOR = { maxFprOutputs: 0.15, minTpr: 0.7 }; // tuned frozen run: test FPR 9.2%, detection 78.0%
const resultsDir = path.join(here, 'results');
fs.mkdirSync(resultsDir, { recursive: true });

interface Summary { outputs: number; flagged: number; fpr: number; randomHits: number; idHits: number; detected: number; total: number; tpr: number }
const summary = (r: SplitReport): Summary => ({
  outputs: r.benign.outputs, flagged: r.benign.flagged, fpr: r.benign.fprOutputs, randomHits: r.benign.randomHits,
  idHits: r.benign.idHits, detected: r.positives.detected, total: r.positives.total, tpr: r.positives.tpr,
});
const current = { dev: summary(dev), test: summary(test), all: summary(all) };
fs.writeFileSync(path.join(resultsDir, 'entropy-bench.json'), JSON.stringify(current, null, 2) + '\n');

// The first detector (PR #2 as opened, commit fff80f6), evaluated by this same benchmark: the "before".
const beforeFile = path.join(resultsDir, 'entropy-bench-before.json');
const before = fs.existsSync(beforeFile) ? (JSON.parse(fs.readFileSync(beforeFile, 'utf8')) as typeof current) : undefined;
const row = (n: string, x: Summary) => `| ${n} | ${x.flagged}/${x.outputs} (${pct(x.fpr)}) | ${x.randomHits} | ${x.idHits} | ${x.detected}/${x.total} (${pct(x.tpr)}) |`;
const shapes = Object.entries(all.benign.byShape).sort((a, b) => b[1].outputs.size - a[1].outputs.size);

const md = [
  '# Entropy detector benchmark (`npm run bench:entropy`)',
  '',
  `Node ${process.version}, ${os.platform()} ${os.arch()}. Deterministic; corpus and seeds in the repository.`,
  'FPR = benign outputs with at least one `random` hit (only `random` hits can escalate). Detection = generated',
  'secrets classified `random`, over every generated secret, including the kinds missed by design.',
  '',
  '| split | benign outputs flagged (FPR) | random hits | id-shaped hits | detection |',
  '|---|---|---|---|---|',
  ...(before ? [row('**before** dev', before.dev), row('**before** test (held out)', before.test)] : []),
  row('after dev', current.dev),
  row('after test (held out)', current.test),
  row('after all', current.all),
  '',
  '"Before" is the first detector (PR #2 as opened), measured by this same benchmark. Tuning used the dev split',
  'only; the test split was run once, after the parameters were frozen.',
  '',
  '**Known defect, seen on the held-out split and deliberately not fixed in this round:** the local part of an',
  'e-mail address (`170738883+…` in a GitHub noreply address) is tokenised as a possible secret; it accounts',
  'for 4 of the 6 flagged held-out outputs. It was also visible on the dev split and was missed during tuning.',
  'Fixing it now would tune against the held-out data, so it is the first item of the next tuning round,',
  'which needs a fresh held-out split.',
  '',
  '## Detection by kind (all splits, after)',
  '',
  '| kind | classified random | classified id | missed |',
  '|---|---|---|---|',
  ...Object.entries(all.positives.byKind).map(([k, v]) => `| ${k} | ${v.random}/${v.total} | ${v.id} | ${v.missed} |`),
  '',
  '## Remaining false positives by token shape (all splits, after)',
  '',
  '| shape | random hits | outputs |',
  '|---|---|---|',
  ...shapes.map(([k, v]) => `| ${k} | ${v.hits} | ${v.outputs.size} |`),
  '',
  '## Remaining false positives by output type (all splits, after)',
  '',
  '| output type | flagged / outputs |',
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
