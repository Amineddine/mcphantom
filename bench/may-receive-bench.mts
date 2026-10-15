/**
 * False-block cost of the `may_receive` fail-closed rule (R6b-1, Phase 7). Deterministic, no model.
 *
 *   npm run bench:may-receive
 *
 * Every call here is benign: its arguments carry nothing from the session's outputs and no credential.
 * A deny is therefore a false block. Calls go to a server with `may_receive: internal` (evidence mode,
 * the default) from three session states:
 *   - `internal only`: the session read internal data only (nothing above the bound);
 *   - `small secret`: it also read a small secret output (a credential), so the context is `secret`;
 *   - `large secret`: the secret output was larger than attribution decodes (128 KiB), so attribution
 *     lost track of secret data for the rest of the session.
 * Reported for four fail-closed rules (below); B is the one implemented, and the run fails if the
 * engine's verdicts disagree with the B column.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ConfigSchema } from '../src/config/schema.js';
import { TaintEngine } from '../src/taint/engine.js';

const here = path.dirname(fileURLToPath(import.meta.url));
// AWS-format credential, assembled at run time so the repository carries no secret-shaped string.
const KEY = ['AKIA', 'BENCHMAYRECEIVE', '1'].join('');

// Deterministic prose (an LCG over a fixed word list), unrelated to any session output.
const WORDS = 'the of and to in report meeting quarterly budget review team project schedule customer release notes draft update plan summary design feedback approve next week status'.split(' ');
// Session outputs use a disjoint vocabulary: with one shared 26-word list, the fuzzy matcher (rightly)
// attributed benign calls to the outputs, which measures the generator, not the rule.
const OUTPUT_WORDS = 'kernel module socket buffer latency cache shard replica index cluster node pod volume mount daemon thread queue worker lease token ledger vault rotation audit'.split(' ');
function prose(chars: number, seed: number, words: string[] = WORDS): string {
  let x = seed >>> 0;
  const out: string[] = [];
  let n = 0;
  while (n < chars) {
    x = (Math.imul(x, 1664525) + 1013904223) >>> 0;
    const w = words[x % words.length] ?? 'x';
    out.push(w);
    n += w.length + 1;
  }
  return out.join(' ').slice(0, chars);
}

const KiB = 1024;
const CALLS: [string, unknown][] = [
  ['1 KiB message', { body: prose(1 * KiB, 1) }],
  ['4 KiB message', { body: prose(4 * KiB, 2) }],
  ['8 KiB message', { body: prose(8 * KiB, 3) }],
  ['16 KiB document', { body: prose(16 * KiB, 4) }],
  ['32 KiB document', { body: prose(32 * KiB, 5) }],
  ['63 KiB document', { body: prose(63 * KiB, 6) }],
  ['65 KiB document', { body: prose(65 * KiB, 7) }],
  ['256 KiB file write', { path: 'notes.md', content: prose(256 * KiB, 8) }],
  ['100 fields of 200 B (JSON batch)', { rows: Array.from({ length: 100 }, (_, i) => ({ id: i, text: prose(200, 100 + i) })) }],
  ['512 short fields', { rows: Array.from({ length: 512 }, (_, i) => `row ${i}`) }],
  ['513 short fields', { rows: Array.from({ length: 513 }, (_, i) => `row ${i}`) }],
  ['2000 short fields', { rows: Array.from({ length: 2000 }, (_, i) => `row ${i}`) }],
  ['40 fields of 2 KiB', { parts: Array.from({ length: 40 }, (_, i) => prose(2 * KiB, 300 + i)) }],
  ['base64 attachment 48 KiB (binary)', { name: 'a.bin', data: Buffer.from(Array.from({ length: 36 * KiB }, (_, i) => (i * 7919) % 256)).toString('base64') }],
];

type State = 'internal only' | 'small secret' | 'large secret';
const STATES: State[] = ['internal only', 'small secret', 'large secret'];

function session(state: State): TaintEngine {
  const t = new TaintEngine(
    ConfigSchema.parse({
      version: 1,
      servers: {
        docs: { command: 'x', defaults: { effect: 'read', integrity: 'trusted', confidentiality: 'internal' } },
        vault: { command: 'x', defaults: { effect: 'read', integrity: 'trusted', confidentiality: 'secret' } },
        sink: { command: 'x', may_receive: 'internal', tools: { send: { effect: 'write', integrity: 'trusted' } } },
      },
    }),
  );
  t.ingest('tool', 'docs', 'docs__get', 'get', { content: [{ type: 'text', text: prose(2 * KiB, 9001, OUTPUT_WORDS) }] });
  if (state === 'small secret') t.ingest('tool', 'vault', 'vault__get', 'get', { content: [{ type: 'text', text: `AWS_ACCESS_KEY_ID=${KEY}\n` }] });
  if (state === 'large secret') t.ingest('tool', 'vault', 'vault__get', 'get', { content: [{ type: 'text', text: `AWS_ACCESS_KEY_ID=${KEY}\n` + prose(140 * KiB, 9002, OUTPUT_WORDS) }] });
  return t;
}

// The options put to the owner, all computed from the same decisions:
//   literal  — deny whenever the decision is degraded (any bound, any session state);
//   A        — degraded by any bound, and what attribution might have missed is above the bound (this
//              call: the context is above it; the session: a lost output was above it);
//   B        — implemented (owner choice, Phase 7): like A, but only the bounds that can hide a credential, an identifier or a verbatim copy
//              (field count, field size, call size, decode budget/limit; evicted or partly decoded
//              outputs) — not the similarity matchers (fuzzy, cumulative);
//   C        — like B, without partly decoded outputs (only clear-text-indexed data counts).
const HIDING = new Set(['leaves', 'leaf-size', 'call-size', 'decode-budget', 'decode-limit']);
type Option = 'literal' | 'A' | 'B' | 'C';
const OPTIONS: Option[] = ['literal', 'A', 'B', 'C'];
function verdictUnder(o: Option, d: { verdict: string; reason: string; attributionDegraded: boolean; degradedBy: string[] }, contextAbove: boolean, lostAbove: boolean): string {
  // A deny for another reason (a credential, Layer-2 evidence, policy) stands under every option.
  if (d.verdict === 'deny' && !d.reason.includes('fail-closed')) return 'deny';
  const call = d.degradedBy.filter((c) => c !== 'evicted' && c !== 'output-decode');
  const session = d.degradedBy.filter((c) => c === 'evicted' || c === 'output-decode');
  if (o === 'literal') return d.attributionDegraded ? 'deny' : 'allow';
  const callCauses = o === 'A' ? call : call.filter((c) => HIDING.has(c));
  const sessionCauses = o === 'C' ? session.filter((c) => c === 'evicted') : session;
  if (callCauses.length > 0 && contextAbove) return 'deny';
  if (sessionCauses.length > 0 && lostAbove) return 'deny';
  return 'allow';
}

interface Row { call: string; state: State; verdict: string; degradedBy: string; options: Record<Option, string>; reason: string; ms: number }
const rows: Row[] = [];
const SEQUENCE = 'small message after 10 earlier 2 KiB sends to the same tool';
for (const state of STATES) {
  const above = state !== 'internal only';
  const lostAbove = state === 'large secret';
  const run = (call: string, t: TaintEngine, args: unknown) => {
    const t0 = performance.now();
    const d = t.decide('sink', 'send', 'sink__send', args);
    const ms = performance.now() - t0;
    const options = Object.fromEntries(OPTIONS.map((o) => [o, verdictUnder(o, d, above, lostAbove)])) as Record<Option, string>;
    rows.push({ call, state, verdict: d.verdict, degradedBy: d.degradedBy.join(', ') || '—', options, reason: d.verdict === 'deny' ? d.reason : '', ms });
  };
  for (const [call, args] of CALLS) run(call, session(state), args);
  const t = session(state);
  for (let i = 0; i < 10; i++) t.sent('sink__send', { body: prose(2 * KiB, 500 + i) });
  run(SEQUENCE, t, { body: prose(1 * KiB, 600) });
}

const rate = (s: State, o: Option | 'verdict') => {
  const r = rows.filter((x) => x.state === s);
  return `${r.filter((x) => (o === 'verdict' ? x.verdict : x.options[o]) === 'deny').length}/${r.length}`;
};
const lines: string[] = [];
const w = (s = '') => lines.push(s);
w('# `may_receive` fail-closed: false-block cost on benign calls (`npm run bench:may-receive`)');
w('');
w(`Generated ${new Date().toISOString()} · ${os.cpus()[0]?.model ?? '?'}, Node ${process.version}. Every call is benign, so every deny is a false block. Server bound: \`may_receive: internal\`, evidence mode. Options: see the header of \`bench/may-receive-bench.mts\`.`);
w('');
w('| session state | literal | A (any bound) | B (implemented: hiding bounds only) | C (B, clear-text losses only) |');
w('|---|---|---|---|---|');
for (const s of STATES) w(`| ${s} | ${rate(s, 'literal')} | ${rate(s, 'A')} | ${rate(s, 'B')} | ${rate(s, 'C')} |`);
w('');
w('| call | session | degraded by | literal | A | B | C | decide ms |');
w('|---|---|---|---|---|---|---|---|');
for (const r of rows) w(`| ${r.call} | ${r.state} | ${r.degradedBy} | ${r.options.literal} | ${r.options.A} | ${r.options.B} | ${r.options.C} | ${r.ms.toFixed(1)} |`);
w('');
fs.mkdirSync(path.join(here, 'results'), { recursive: true });
fs.writeFileSync(path.join(here, 'results', 'may-receive-bench.md'), lines.join('\n'));
fs.writeFileSync(path.join(here, 'results', 'may-receive-bench.json'), JSON.stringify(rows.map(({ ms: _ms, ...r }) => r), null, 1) + '\n');
process.stdout.write(lines.slice(0, 10).join('\n') + '\n');
const drift = rows.filter((r) => r.verdict !== r.options.B);
if (drift.length > 0) {
  process.stderr.write(`\nFAIL: the engine's verdict differs from option B on: ${drift.map((r) => `${r.call} / ${r.state}`).join('; ')}\n`);
  process.exitCode = 1;
}
