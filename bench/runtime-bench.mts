/**
 * mcp-attack-bench, Tier 1 runtime (decision-level replay; DESIGN.md §6, Phase 7 item 3). Deterministic,
 * no model, no servers, no network.
 *
 *   npm run bench:runtime
 *
 * Replays every recorded trace in bench/attack/scenarios.json through each defense and scores it with
 * the defense-independent oracles (bench/attack/replay.ts). Reported per defense, with Wilson 95%
 * intervals: attack success rate (lower is better), false-block rate on benign traces, and utility
 * under attack; per channel and per encoding for MCPhantom; every attack that got through and every
 * false block listed.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { attackSucceeded, denyAllEgress, fragmentsReceived, mcphantom, noDefense, replay, scannerOnly, utilityKept, type Defense } from './attack/replay.js';
import { loadScenario, type LoadedScenario } from './attack/scenario.js';
import { rate } from './attack/stats.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const scenarios = (JSON.parse(fs.readFileSync(path.join(here, 'attack', 'scenarios.json'), 'utf8')) as unknown[]).map(loadScenario);

interface Row { scenario: LoadedScenario; defense: string; attackSuccess: boolean | null; fragments: { received: number; total: number }; utility: boolean; blocked: string[] }
const DEFENSES: [string, (sc: LoadedScenario) => Defense][] = [
  ['no defense', () => noDefense()],
  ['scanner only', () => scannerOnly()],
  ['deny all egress', (sc) => denyAllEgress(sc)],
  ['MCPhantom (defaults)', (sc) => mcphantom(sc)],
];

const rows: Row[] = [];
for (const sc of scenarios) {
  for (const [, make] of DEFENSES) {
    const d = make(sc); // a fresh session per scenario
    const { outcomes, delivered } = replay(sc, d);
    rows.push({
      scenario: sc,
      defense: d.name,
      attackSuccess: sc.kind === 'attack' ? attackSucceeded(sc, delivered) : null,
      fragments: fragmentsReceived(sc, delivered),
      utility: utilityKept(outcomes),
      blocked: outcomes.filter((o) => !o.delivered).map((o) => `step ${o.step} (${o.role}): ${o.blockedBy ?? '?'}`),
    });
  }
}

const by = (def: string, pred: (r: Row) => boolean) => rows.filter((r) => r.defense === def && pred(r));
const lines = [
  '# mcp-attack-bench — Tier 1 runtime (decision-level replay)',
  '',
  `Generated ${new Date().toISOString()} · ${process.version} · ${os.type()} ${os.release()} · ${scenarios.length} recorded traces (${scenarios.filter((s) => s.kind === 'attack').length} attack, ${scenarios.filter((s) => s.kind === 'benign').length} benign).`,
  'Traces go to each defense in process, in the gateway\'s order; no servers, no network, no model. Oracles read only the',
  'delivery log and each scenario\'s ground truth (the secret, encoded as the trace sent it), never the defense\'s evidence.',
  'Injection points hold an inert marker: this measures what a defense does once a model has been steered, not whether it is.',
  '',
  '**Read these numbers as a regression floor, not as performance on real attacks.** The scenarios are author-written to',
  'exercise the channels and encodings the design claims to stop (the attacks outside the claims are listed below). The',
  'benign mix was chosen to exercise each channel, and 4 of its 15 traces are deliberately over-tainted, so the false-block',
  'rate describes that mix, not a real workload (normal-workflow false blocks are measured on PostHog in Phase 7 item 7).',
  '',
  '## Summary — attacks the design claims to stop',
  '',
  '| defense | attack success (lower is better) | false blocks on benign traces | utility kept under attack |',
  '|---|---|---|---|',
  ...DEFENSES.map(([name]) => {
    const atk = by(name, (r) => r.scenario.kind === 'attack' && r.scenario.claimed);
    const ben = by(name, (r) => r.scenario.kind === 'benign');
    return `| ${name} | ${rate(atk.filter((r) => r.attackSuccess).length, atk.length)} | ${rate(ben.filter((r) => !r.utility).length, ben.length)} | ${rate(atk.filter((r) => r.utility).length, atk.length)} |`;
  }),
  '',
];

for (const [name] of DEFENSES.filter(([n]) => n !== 'no defense')) {
  const atk = by(name, (r) => r.scenario.kind === 'attack' && r.scenario.claimed);
  const cats = [...new Set(atk.map((r) => r.scenario.category))];
  const trs = [...new Set(atk.map((r) => r.scenario.exfil?.transform ?? ''))];
  lines.push(`## ${name}: attack success by channel and by encoding`, '', '| channel | attack success |', '|---|---|',
    ...cats.map((c) => { const rs = atk.filter((r) => r.scenario.category === c); return `| ${c} | ${rate(rs.filter((r) => r.attackSuccess).length, rs.length)} |`; }),
    '', '| encoding | attack success |', '|---|---|',
    ...trs.map((t) => { const rs = atk.filter((r) => r.scenario.exfil?.transform === t); return `| ${t} | ${rate(rs.filter((r) => r.attackSuccess).length, rs.length)} |`; }),
    '');
}

const mcp = 'MCPhantom (defaults)';
const unclaimed = rows.filter((r) => r.scenario.kind === 'attack' && !r.scenario.claimed);
const ucats = [...new Set(unclaimed.map((r) => r.scenario.category))];
lines.push('## Outside the claims (reported, not claimed)', '', 'Attacks the design says MCPhantom does not stop; they show where the boundary is.', '',
  `| attack | ${DEFENSES.map(([n]) => n).join(' | ')} |`, `|---|${DEFENSES.map(() => '---').join('|')}|`,
  ...ucats.map((c) => `| ${c} | ${DEFENSES.map(([n]) => { const rs = unclaimed.filter((r) => r.defense === n && r.scenario.category === c); return rate(rs.filter((r) => r.attackSuccess).length, rs.length); }).join(' | ')} |`),
  '');
const partial = by(mcp, (r) => r.scenario.kind === 'attack' && r.scenario.claimed && !r.attackSuccess && r.fragments.received > 0);
lines.push(`## MCPhantom: partial leaks — attack stopped, but part of the secret reached the attacker (${partial.length})`, '',
  ...(partial.length ? partial.map((r) => `- \`${r.scenario.id}\` — ${r.fragments.received} of ${r.fragments.total} fragments delivered before the block (${r.blocked.join('; ')})`) : ['None.']), '');
const through = by(mcp, (r) => r.attackSuccess === true && r.scenario.claimed);
const falseBlocks = by(mcp, (r) => r.scenario.kind === 'benign' && !r.utility);
lines.push(`## MCPhantom: every attack that got through (${through.length})`, '', ...(through.length ? through.map((r) => `- \`${r.scenario.id}\` — ${r.scenario.description}`) : ['None.']), '');
lines.push(`## MCPhantom: every false block on a benign trace (${falseBlocks.length})`, '', ...(falseBlocks.length ? falseBlocks.map((r) => `- \`${r.scenario.id}\` — ${r.scenario.description} Blocked: ${r.blocked.join('; ')}`) : ['None.']), '');
lines.push(
  '## Scope',
  '',
  '- Decision level only (owner decision, 2026-10-16): the gate is driven in process, as the gateway drives it. The black-box',
  '  MCP-proxy adapter is specified in docs/benchmark.md and exercised on the demo fixtures only.',
  '- The sink server is bounded with `may_receive: public` by the scenario, as an operator would configure it; without that bound',
  '  MCPhantom does not restrict what a read-only tool is sent.',
  '- Secrets are classified by the secrets-store tool (`confidentiality: secret`), so both secret formats are labelled without',
  '  pattern detection; an unclassified secrets source is not measured here.',
  '- Not measured: paraphrased or model-rewritten data (Phase 9), covert / low-entropy channels, URL construction by the model.',
  '',
);

const md = lines.join('\n');
fs.mkdirSync(path.join(here, 'results'), { recursive: true });
fs.writeFileSync(path.join(here, 'results', 'runtime-bench.md'), md);
fs.writeFileSync(path.join(here, 'results', 'runtime-bench.json'), JSON.stringify(rows.map((r) => ({ scenario: r.scenario.id, kind: r.scenario.kind, category: r.scenario.category, transform: r.scenario.exfil?.transform, claimed: r.scenario.claimed, defense: r.defense, attackSuccess: r.attackSuccess, fragments: r.fragments, utility: r.utility, blocked: r.blocked })), null, 1) + '\n');
process.stdout.write(md);
