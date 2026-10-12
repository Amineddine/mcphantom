/**
 * Minimal line diff (LCS) for showing config changes before they are applied. Inputs are small
 * (client config files), so O(n·m) is fine; a hard cap keeps it bounded.
 */
export function lineDiff(before: string, after: string, context = 3): string {
  const a = before.split('\n');
  const b = after.split('\n');
  if (a.length * b.length > 4_000_000) return `--- before (${a.length} lines)\n+++ after (${b.length} lines)\n(diff too large to display)`;
  const n = a.length;
  const m = b.length;
  const lcs: Uint32Array[] = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    const row = lcs[i] as Uint32Array;
    const next = lcs[i + 1] as Uint32Array;
    for (let j = m - 1; j >= 0; j--) {
      row[j] = a[i] === b[j] ? (next[j + 1] as number) + 1 : Math.max(next[j] as number, row[j + 1] as number);
    }
  }
  const ops: { t: ' ' | '-' | '+'; s: string }[] = [];
  let i = 0;
  let j = 0;
  while (i < n || j < m) {
    if (i < n && j < m && a[i] === b[j]) {
      ops.push({ t: ' ', s: a[i] as string });
      i++;
      j++;
    } else if (j < m && (i >= n || (lcs[i]?.[j + 1] ?? 0) >= (lcs[i + 1]?.[j] ?? 0))) {
      ops.push({ t: '+', s: b[j] as string });
      j++;
    } else {
      ops.push({ t: '-', s: a[i] as string });
      i++;
    }
  }
  const keep = new Array<boolean>(ops.length).fill(false);
  ops.forEach((op, k) => {
    if (op.t !== ' ') for (let d = Math.max(0, k - context); d <= Math.min(ops.length - 1, k + context); d++) keep[d] = true;
  });
  const out: string[] = [];
  let skipped = false;
  ops.forEach((op, k) => {
    if (keep[k]) {
      out.push(`${op.t} ${op.s}`);
      skipped = false;
    } else if (!skipped) {
      out.push('  ...');
      skipped = true;
    }
  });
  return out.join('\n');
}
