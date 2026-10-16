/**
 * mcp-attack-bench, baselines and ablations (Phase 7 item 4; pre-registered in
 * bench/attack/PREREGISTRATION-ablations.md). Deterministic, no model, no servers, no network.
 *
 *   npm run bench:ablations
 *
 * Replays three trace sets through every configuration with the defense-independent oracles
 * (bench/attack/replay.ts): the item-3 suite (scenarios.json, unchanged), the policy family
 * (scenarios-policy.json: author-written from() rules and a declassify) and the unclassified-source
 * family (scenarios-unclassified.json: entropy on_hit). The sets are reported in their own tables and
 * never pooled. Every table carries attack success, partial leaks, false blocks and utility under
 * attack, with Wilson 95% intervals; every ablation lists the traces whose outcome differs from defaults.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { attackSucceeded, denyAllEgress, fragmentsReceived, mcphantom, noDefense, replay, scannerOnly, utilityKept, type Defense, type MCPhantomOptions } from './attack/replay.js';
import { loadScenario, type LoadedScenario } from './attack/scenario.js';
import { rate } from './attack/stats.js';
import { MATCHERS, type Matcher } from '../src/taint/provenance.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const load = (f: string) => (JSON.parse(fs.readFileSync(path.join(here, 'attack', f), 'utf8')) as unknown[]).map(loadScenario);
const SETS: { id: string; title: string; file: string; scenarios: LoadedScenario[] }[] = [
  { id: 'suite', title: 'Item-3 suite (83 traces, unchanged)', file: 'scenarios.json', scenarios: load('scenarios.json') },
  { id: 'policy', title: 'Policy family (from() rules and a declassify)', file: 'scenarios-policy.json', scenarios: load('scenarios-policy.json') },
  { id: 'unclassified', title: 'Unclassified-source family (entropy on_hit)', file: 'scenarios-unclassified.json', scenarios: load('scenarios-unclassified.json') },
];

const without = (...off: Matcher[]) => new Set(MATCHERS.filter((m) => !off.includes(m)));
const mcp = (name: string, o: Omit<MCPhantomOptions, 'name'> = {}) => (sc: LoadedScenario) => mcphantom(sc, { ...o, name });
const LAYER1 = { matchers: new Set<Matcher>() };
const CONFIGS: { id: string; name: string; make: (sc: LoadedScenario) => Defense }[] = [
  { id: 'B1', name: 'no defense', make: () => noDefense() },
  { id: 'B2', name: 'scanner only', make: () => scannerOnly() },
  { id: 'B3', name: 'deny all egress', make: (sc) => denyAllEgress(sc) },
  { id: 'C0', name: 'MCPhantom (defaults)', make: mcp('MCPhantom (defaults)') },
  { id: 'C1', name: 'Layer 1 only', make: mcp('Layer 1 only', { ablation: LAYER1 }) },
  { id: 'C1x', name: 'Layer 1 only, no argument credential check', make: mcp('Layer 1 only, no argument credential check', { ablation: { ...LAYER1, argCredentials: false } }) },
  ...MATCHERS.map((m, i) => ({ id: `C${i + 2}`, name: `${m} off`, make: mcp(`${m} off`, { ablation: { matchers: without(m) } }) })),
  { id: 'C7', name: 'scanner off', make: mcp('scanner off', { extra: { scan: { enabled: false } } }) },
  { id: 'C8', name: 'entropy on_hit: internal', make: mcp('entropy on_hit: internal', { extra: { secrets: { entropy: { on_hit: 'internal' } } } }) },
  { id: 'C9', name: 'entropy on_hit: secret', make: mcp('entropy on_hit: secret', { extra: { secrets: { entropy: { on_hit: 'secret' } } } }) },
  { id: 'C10', name: 'may_receive_mode: context', make: mcp('may_receive_mode: context', { mayReceiveMode: 'context' }) },
  { id: 'C11', name: 'Layer 1 only + context mode', make: mcp('Layer 1 only + context mode', { ablation: LAYER1, mayReceiveMode: 'context' }) },
  { id: 'C12', name: 'trifecta: log (audit mode)', make: mcp('trifecta: log (audit mode)', { extra: { taint: { trifecta: 'log' } } }) },
];

interface Row { set: string; config: string; scenario: LoadedScenario; success: boolean | null; fragments: { received: number; total: number }; utility: boolean; blocked: string[] }
const rows: Row[] = [];
for (const set of SETS) {
  for (const sc of set.scenarios) {
    for (const c of CONFIGS) {
      const { outcomes, delivered } = replay(sc, c.make(sc)); // a fresh session per trace
      rows.push({
        set: set.id, config: c.id, scenario: sc,
        success: sc.kind === 'attack' ? attackSucceeded(sc, delivered) : null,
        fragments: fragmentsReceived(sc, delivered),
        utility: utilityKept(outcomes),
        blocked: outcomes.filter((o) => !o.delivered).map((o) => `step ${o.step} (${o.role}): ${o.blockedBy ?? '?'}`),
      });
    }
  }
}

const partialLeak = (r: Row) => r.success === false && r.fragments.received > 0;
/** One trace's outcome in words, for the "differs from defaults" lists. */
function outcome(r: Row): string {
  if (r.scenario.kind === 'benign') return r.utility ? 'delivered' : `false block (${r.blocked.join('; ')})`;
  if (r.success) return 'attack succeeded';
  if (partialLeak(r)) return `partial leak ${r.fragments.received}/${r.fragments.total} (${r.blocked.join('; ')})`;
  return `stopped (${r.blocked.filter((b) => b.includes('(attack)')).join('; ') || r.blocked.join('; ')})`;
}
const get = (set: string, config: string) => rows.filter((r) => r.set === set && r.config === config);

const lines: string[] = [
  '# mcp-attack-bench — baselines and ablations',
  '',
  `Generated ${new Date().toISOString()} · ${process.version} · ${os.type()} ${os.release()} · pre-registered in`,
  '`bench/attack/PREREGISTRATION-ablations.md` (committed and pushed before the first run).',
  'Decision-level replay, as in `bench/results/runtime-bench.md`: no servers, no network, no model; the oracles read only',
  'the delivery log and each trace\'s ground truth. **Author-written traces: a regression floor and a map of which part of',
  'the design stops what, not performance on real attacks.**',
  '',
  '**Under the default configuration Layer 2 does not change any trifecta decision:** the trifecta invariant reads the',
  'Layer-1 context label only. Layer-2 evidence decides only the `may_receive` bound and `from()` policy predicates, so its',
  'contribution shows on the bounded sink server (item-3 suite) and in the policy family, nowhere else.',
  '',
  'Columns: **attack success** — every fragment of the secret reached the attacker (claimed attacks; lower is better);',
  '**partial leaks** — attack stopped, but some fragments were delivered first (same denominator; only split secrets can',
  'leak in part); **false blocks** — benign traces with a benign step not delivered; **utility under attack** — attack',
  'traces whose benign steps were all delivered. Wilson 95% intervals.',
  '',
  '## Configurations',
  '',
  '| id | configuration |',
  '|---|---|',
  ...CONFIGS.map((c) => `| ${c.id} | ${c.name} |`),
  '',
  'Ablations are internal switches no configuration can reach (`test/ablation-hook.test.ts`); a matcher is turned off',
  'where it runs (with `exact` off a verbatim copy can still be found as `normalized`). C1 keeps the `may_receive`',
  'clear-text credential search over arguments (pattern detection, not attribution); C1x turns it off as well.',
  '',
];

for (const set of SETS) {
  const claimed = set.scenarios.filter((s) => s.kind === 'attack' && s.claimed);
  const outside = set.scenarios.filter((s) => s.kind === 'attack' && !s.claimed);
  const benign = set.scenarios.filter((s) => s.kind === 'benign');
  lines.push(`## ${set.title}`, '', `\`bench/attack/${set.file}\`: ${claimed.length} claimed attacks, ${outside.length} outside the claims, ${benign.length} benign.`, '');
  if (set.id === 'unclassified') lines.push('No attack in this family is claimed at defaults (entropy alone does not raise the label; owner decision 2026-10-13), so', 'its attacks are scored here as a family of their own, under every configuration.', '');
  const atkSet = set.id === 'unclassified' ? set.scenarios.filter((s) => s.kind === 'attack') : claimed;
  lines.push('| id | configuration | attack success | partial leaks | false blocks | utility under attack |', '|---|---|---|---|---|---|');
  for (const c of CONFIGS) {
    const rs = get(set.id, c.id);
    const atk = rs.filter((r) => atkSet.includes(r.scenario));
    const ben = rs.filter((r) => r.scenario.kind === 'benign');
    lines.push(`| ${c.id} | ${c.name} | ${rate(atk.filter((r) => r.success).length, atk.length)} | ${rate(atk.filter(partialLeak).length, atk.length)} | ${rate(ben.filter((r) => !r.utility).length, ben.length)} | ${rate(atk.filter((r) => r.utility).length, atk.length)} |`);
  }
  lines.push('');
  if (outside.length && set.id !== 'unclassified') {
    lines.push('Outside the claims (reported, not claimed):', '', '| id | configuration | attack success | partial leaks |', '|---|---|---|---|');
    for (const c of CONFIGS) {
      const rs = get(set.id, c.id).filter((r) => outside.includes(r.scenario));
      lines.push(`| ${c.id} | ${c.name} | ${rate(rs.filter((r) => r.success).length, rs.length)} | ${rate(rs.filter(partialLeak).length, rs.length)} |`);
    }
    lines.push('');
  }
  lines.push(`### ${set.id === 'suite' ? 'Item-3 suite' : set.title.split(' (')[0]}: every trace whose outcome differs from MCPhantom (defaults)`, '');
  const base = new Map(get(set.id, 'C0').map((r) => [r.scenario.id, outcome(r)]));
  for (const c of CONFIGS.filter((x) => x.id.startsWith('C') && x.id !== 'C0')) {
    const diff = get(set.id, c.id).filter((r) => outcome(r) !== base.get(r.scenario.id));
    lines.push(`**${c.id} ${c.name}** — ${diff.length === 0 ? 'no change.' : `${diff.length} changed:`}`);
    for (const r of diff) lines.push(`- \`${r.scenario.id}\`: ${base.get(r.scenario.id)} → ${outcome(r)}`);
    lines.push('');
  }
}

const md = lines.join('\n');
fs.mkdirSync(path.join(here, 'results'), { recursive: true });
fs.writeFileSync(path.join(here, 'results', 'ablations.md'), md);
fs.writeFileSync(path.join(here, 'results', 'ablations.json'), JSON.stringify(rows.map((r) => ({ set: r.set, config: r.config, scenario: r.scenario.id, kind: r.scenario.kind, claimed: r.scenario.claimed, success: r.success, fragments: r.fragments, utility: r.utility, blocked: r.blocked })), null, 1) + '\n');
process.stdout.write(md);
