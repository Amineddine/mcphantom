/** Wilson score interval, 95%. */
const Z = 1.959963984540054;
export function wilson(k: number, n: number): [number, number] {
  if (n === 0) return [NaN, NaN];
  const p = k / n;
  const d = 1 + (Z * Z) / n;
  const c = (p + (Z * Z) / (2 * n)) / d;
  const h = (Z * Math.sqrt((p * (1 - p)) / n + (Z * Z) / (4 * n * n))) / d;
  return [Math.max(0, c - h), Math.min(1, c + h)];
}

export const pct = (x: number) => (Number.isNaN(x) ? 'n/a' : `${(x * 100).toFixed(1)}%`);

/** "k / n (rate, CI lo – hi)". */
export function rate(k: number, n: number): string {
  const [lo, hi] = wilson(k, n);
  return `${k} / ${n} (${pct(k / n)}; ${pct(lo)} – ${pct(hi)})`;
}
