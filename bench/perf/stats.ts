/**
 * Statistics for `bench:perf` (pre-registered in bench/perf/PREREGISTRATION-perf.md): nearest-rank
 * percentiles on pooled samples, and a cluster bootstrap that resamples the top level (VM on CI, launch on
 * the laptop), then each level below, then samples. Calls inside one process are correlated; pooling them
 * as if independent would make the intervals too narrow.
 */

/** Samples nested by cluster: `[vm][launch][sample]`. The laptop has a single VM-level group. */
export type Nested = number[][][];

export const BOOTSTRAP_B = 2000;
export const BOOTSTRAP_SEED = 20261017;

/** Nearest-rank percentile, as in Phase 1 (`bench/latency.ts`). */
export function percentile(samples: readonly number[], q: number): number {
  if (samples.length === 0) return NaN;
  const s = [...samples].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor(q * s.length))] ?? NaN;
}

export function mean(xs: readonly number[]): number {
  return xs.length === 0 ? NaN : xs.reduce((a, b) => a + b, 0) / xs.length;
}

export function median(xs: readonly number[]): number {
  return percentile(xs, 0.5);
}

/** Coefficient of variation (sample SD / mean). */
export function cv(xs: readonly number[]): number {
  if (xs.length < 2) return NaN;
  const m = mean(xs);
  const sd = Math.sqrt(xs.reduce((a, x) => a + (x - m) ** 2, 0) / (xs.length - 1));
  return sd / m;
}

/** mulberry32: small, seeded, reproducible. */
export function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const pick = <T>(xs: readonly T[], r: () => number): T => xs[Math.floor(r() * xs.length)] as T;

/** One bootstrap resample of the nested structure, pooled: VMs, then launches within each, then samples. */
function resample(groups: Nested, r: () => number, idx?: number[][]): number[] {
  const out: number[] = [];
  for (let v = 0; v < groups.length; v++) {
    const vi = idx ? (idx[v]?.[0] ?? 0) : Math.floor(r() * groups.length);
    const vm = groups[vi] ?? [];
    for (let l = 0; l < vm.length; l++) {
      const li = idx ? (idx[v]?.[l + 1] ?? 0) : Math.floor(r() * vm.length);
      const launch = vm[li] ?? [];
      for (let s = 0; s < launch.length; s++) out.push(pick(launch, r));
    }
  }
  return out;
}

/** Draws the cluster indices (VM, then launch) for one resample, so two arms can share them (paired). */
function drawIndices(shape: number[], r: () => number): number[][] {
  return shape.map(() => {
    const vi = Math.floor(r() * shape.length);
    const n = shape[vi] ?? 0;
    return [vi, ...Array.from({ length: n }, () => Math.floor(r() * n))];
  });
}

export interface Estimate { value: number; lo: number; hi: number }

const sortedPct = (s: readonly number[], q: number) => s[Math.min(s.length - 1, Math.floor(q * s.length))] ?? NaN;
const sorted = (xs: number[]) => xs.sort((a, b) => a - b);

/** Percentiles `qs` of the pooled samples, each with a 95% cluster-bootstrap interval (one resample serves all `qs`). */
export function bootstrapQuantiles(groups: Nested, qs: readonly number[], seed = BOOTSTRAP_SEED, b = BOOTSTRAP_B): Estimate[] {
  const r = rng(seed);
  const stats: number[][] = qs.map(() => []);
  for (let i = 0; i < b; i++) {
    const s = sorted(resample(groups, r));
    qs.forEach((q, j) => stats[j]?.push(sortedPct(s, q)));
  }
  const all = sorted(groups.flat(2));
  return qs.map((q, j) => {
    const st = sorted(stats[j] ?? []);
    return { value: sortedPct(all, q), lo: sortedPct(st, 0.025), hi: sortedPct(st, 0.975) };
  });
}

/**
 * Percentiles of arm `a` minus those of arm `b`, bootstrapped paired at the cluster level: both arms are
 * resampled with the same VMs and launches (they were interleaved inside each launch). Arms must have the
 * same nesting shape (sample counts may differ).
 */
export function bootstrapDeltas(a: Nested, b: Nested, qs: readonly number[], seed = BOOTSTRAP_SEED, n = BOOTSTRAP_B): Estimate[] {
  const shape = a.map((vm) => vm.length);
  if (b.length !== a.length || b.some((vm, i) => vm.length !== shape[i])) throw new Error('bootstrapDeltas: arms differ in shape');
  const r = rng(seed);
  const stats: number[][] = qs.map(() => []);
  for (let i = 0; i < n; i++) {
    const idx = drawIndices(shape, r);
    const sa = sorted(resample(a, r, idx));
    const sb = sorted(resample(b, r, idx));
    qs.forEach((q, j) => stats[j]?.push(sortedPct(sa, q) - sortedPct(sb, q)));
  }
  const aa = sorted(a.flat(2));
  const bb = sorted(b.flat(2));
  return qs.map((q, j) => {
    const st = sorted(stats[j] ?? []);
    return { value: sortedPct(aa, q) - sortedPct(bb, q), lo: sortedPct(st, 0.025), hi: sortedPct(st, 0.975) };
  });
}

/** Run-to-run variance: p50 of each launch (min / median / max, CV) and of each VM. */
export function spread(groups: Nested): { launchP50: { min: number; median: number; max: number; cv: number }; vmP50: number[] } {
  const perLaunch = groups.flatMap((vm) => vm.map((l) => percentile(l, 0.5)));
  return {
    launchP50: { min: Math.min(...perLaunch), median: median(perLaunch), max: Math.max(...perLaunch), cv: cv(perLaunch) },
    vmP50: groups.map((vm) => percentile(vm.flat(), 0.5)),
  };
}
