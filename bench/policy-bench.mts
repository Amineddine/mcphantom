/**
 * Worst-case policy evaluation cost (owner note #2). Measures a decision with adversarially large and
 * nested arguments against a rule set that exercises every custom predicate, to confirm the per-call
 * cost/time budget holds and that evaluation stays bounded.
 *
 *   npm run bench:policy
 */
import os from 'node:os';
import { performance } from 'node:perf_hooks';
import { ConfigSchema } from '../src/config/schema.js';
import { EVAL_BUDGET_MS, PolicyEngine } from '../src/policy/engine.js';
import { TaintEngine } from '../src/taint/engine.js';

const config = ConfigSchema.parse({
  version: 1,
  servers: {
    mail: {
      command: 'x',
      tools: {
        send: {
          effect: 'egress',
          integrity: 'trusted',
          rules: [
            { deny: 'containsSecret(arg.body)' },
            { deny: 'glob(arg.path, ["**/.env*", "**/.ssh/**", "**/*credentials*"])' },
            { deny: 'from(arg.to, "untrusted")' },
            { ask: 'context.integrity == "untrusted"' },
            { allow: 'within(arg.path, "./workspace")' },
          ],
        },
      },
    },
  },
});

/** Times the whole decision (Layer-2 attribution + policy) and the policy evaluation alone — the part
 *  the EVAL_BUDGET_MS deadline covers — and counts policy evaluations the deadline denied. */
function measure(label: string, args: Record<string, unknown>, n: number): void {
  const engine = new TaintEngine(config, new PolicyEngine(config));
  const policy = new PolicyEngine(config);
  const whole: number[] = [];
  const alone: number[] = [];
  let overBudget = 0;
  for (let i = 0; i < n; i++) {
    let t0 = performance.now();
    engine.decide('mail', 'send', 'mail__send', args);
    whole.push(performance.now() - t0);
    t0 = performance.now();
    const o = policy.evaluate({ serverId: 'mail', toolName: 'send', args, context: { integrity: 'trusted', confidentiality: 'public' }, provenanceOf: () => new Set() });
    alone.push(performance.now() - t0);
    if (o.errors.some((e) => e.message.includes('time budget'))) overBudget++;
  }
  process.stdout.write(`| ${label} | ${stats(whole)} | ${stats(alone)} | ${overBudget}/${n} |\n`);
}

function stats(samples: number[]): string {
  samples.sort((a, b) => a - b);
  const p = (q: number) => samples[Math.min(samples.length - 1, Math.floor(q * samples.length))] ?? NaN;
  return `${p(0.5).toFixed(2)} / ${p(0.95).toFixed(2)} / ${samples[samples.length - 1]?.toFixed(2)} ms`;
}

process.stdout.write(`Policy worst-case evaluation — ${os.cpus()[0]?.model ?? '?'}, Node ${process.version}\n\n`);
process.stdout.write(`Policy deadline: ${EVAL_BUDGET_MS} ms over the whole evaluation. Columns: p50 / p95 / max.\n\n`);
process.stdout.write('| case | whole decision (attribution + policy) | policy evaluation alone | denied by deadline |\n|---|---|---|---|\n');
measure('small args', { to: 'me@corp.example', path: 'workspace/x', body: 'hello' }, 5000);
measure('128 KB body', { to: 'me@corp.example', path: 'workspace/x', body: 'a '.repeat(64 * 1024) }, 300);
measure('deeply nested args', nest(5000), 500);
measure('many keys (4000, under the field cap)', manyKeys(4000), 500);
measure('too many keys (5000, expect fast deny)', manyKeys(5000), 500);
measure('over-budget body (expect fast deny)', { to: 'me@corp.example', path: 'x', body: 'a'.repeat(512 * 1024) }, 200);

process.stdout.write('\nThe over-budget case denies immediately on the size check (note #2); no rule runs on it.\n');

function nest(depth: number): Record<string, unknown> {
  let v: unknown = 'leaf';
  for (let i = 0; i < depth; i++) v = { to: 'me@corp.example', path: 'workspace/x', body: 'b', child: v };
  return v as Record<string, unknown>;
}
function manyKeys(n: number): Record<string, unknown> {
  const o: Record<string, unknown> = { to: 'me@corp.example', path: 'workspace/x', body: 'b' };
  for (let i = 0; i < n; i++) o[`k${i}`] = `v${i}`;
  return o;
}
