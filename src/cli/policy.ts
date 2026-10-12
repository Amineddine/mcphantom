import fs from 'node:fs';
import path from 'node:path';
import { parse as parseYaml } from 'yaml';
import { loadConfigFile } from '../config/load.js';
import type { Paths } from '../config/paths.js';
import { BOTTOM, type Label } from '../taint/labels.js';
import { TaintEngine } from '../taint/engine.js';
import { PolicyEngine } from '../policy/engine.js';
import { lintPolicy, schemaArgNames, type LintIssue } from '../policy/lint.js';
import { collectSchemas } from './schemas.js';
import { UserError } from '../util/errors.js';

export interface PolicyIo {
  out(text: string): void;
}

/** `mcphantom policy lint`: lint rules against live tool schemas (same source approve pins from). */
export async function runPolicyLint(configFile: string, paths: Paths, io: PolicyIo): Promise<number> {
  const { config } = loadConfigFile(configFile);
  const schemas = await collectSchemas(configFile, paths);
  const issues = lintPolicy(config, schemas);
  return reportLint(issues, io);
}

export function reportLint(issues: LintIssue[], io: PolicyIo): number {
  if (issues.length === 0) {
    io.out('policy: no issues.');
    return 0;
  }
  for (const i of issues) io.out(`  ${i.level === 'error' ? 'ERROR' : 'warn '} ${i.where}: ${i.message}`);
  const errors = issues.filter((i) => i.level === 'error').length;
  io.out(`${errors} error(s), ${issues.length - errors} warning(s).`);
  return errors > 0 ? 1 : 0;
}

interface TestCase {
  name?: string;
  tool: string; // exposed name <server>__<tool>
  args?: Record<string, unknown>;
  context?: { integrity?: Label['integrity']; confidentiality?: Label['confidentiality'] };
  /** Ingest these before deciding, to set up the session context deterministically. */
  ingest?: { server: string; name: string; text: string }[];
  expect: 'allow' | 'ask' | 'deny';
}

/** `mcphantom policy test <fixtures.yaml>`: run decision cases against the configured policy. */
export function runPolicyTest(configFile: string, fixturesFile: string, io: PolicyIo): number {
  const { config } = loadConfigFile(configFile);
  let cases: TestCase[];
  try {
    cases = parseYaml(fs.readFileSync(fixturesFile, 'utf8')) as TestCase[];
  } catch (err) {
    throw new UserError(`Could not read fixtures ${fixturesFile}: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (!Array.isArray(cases)) throw new UserError('Fixtures file must be a YAML list of cases.');
  let failed = 0;
  for (const [i, c] of cases.entries()) {
    const engine = new TaintEngine(config, new PolicyEngine(config));
    for (const ing of c.ingest ?? []) engine.ingest('tool', ing.server, `${ing.server}__${ing.name}`, ing.name, { content: [{ type: 'text', text: ing.text }] });
    const parts = c.tool.split('__');
    const serverId = parts[0] ?? '';
    const toolName = parts.slice(1).join('__');
    // Force the context label if the case specifies one (overrides ingest-derived context).
    if (c.context) engine.context = { integrity: c.context.integrity ?? BOTTOM.integrity, confidentiality: c.context.confidentiality ?? BOTTOM.confidentiality };
    const d = engine.decide(serverId, toolName, c.tool, c.args ?? {});
    const got = d.verdict;
    const ok = got === c.expect;
    if (!ok) failed++;
    io.out(`  ${ok ? 'PASS' : 'FAIL'} [${i}] ${c.name ?? c.tool} — expected ${c.expect}, got ${got}${ok ? '' : ` (${d.reason})`}`);
  }
  io.out(`${cases.length - failed}/${cases.length} passed.`);
  return failed > 0 ? 1 : 0;
}

/** `mcphantom policy explain --tool <t> [--arg k=v ...]`: dry-run which rules match and the verdict. */
export function runPolicyExplain(configFile: string, tool: string, args: Record<string, unknown>, context: Label, io: PolicyIo): number {
  const { config } = loadConfigFile(configFile);
  const engine = new TaintEngine(config, new PolicyEngine(config));
  engine.context = context;
  const parts = tool.split('__');
  const d = engine.decide(parts[0] ?? '', parts.slice(1).join('__'), tool, args);
  io.out(`${tool}: ${d.verdict.toUpperCase()}${d.rule ? ` (${d.rule})` : ''}`);
  io.out(`  context: ${context.integrity}/${context.confidentiality}; effect: ${d.effect}`);
  io.out(`  reason:  ${d.reason}`);
  for (const m of d.policy?.matches ?? []) io.out(`  matched: ${m.effect} ← ${m.origin}`);
  for (const e of d.policy?.errors ?? []) io.out(`  error:   ${e.origin}: ${e.message}`);
  if (d.policy?.declassified) io.out(`  declassify: ${d.policy.declassified.id} (${d.policy.declassified.reason})`);
  return 0;
}

export { schemaArgNames, collectSchemas };
export type { Paths };
export function configDirOf(paths: Paths): string {
  return path.resolve(paths.configDir);
}
