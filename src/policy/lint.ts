import type { Config } from '../config/schema.js';
import { CelError } from './cel.js';
import { PolicyEngine } from './engine.js';
import { PRECISION_FUNCTIONS } from './functions.js';

export interface LintIssue {
  level: 'error' | 'warning';
  where: string;
  message: string;
}

/** Argument names a tool's input schema declares (top-level properties). */
export function schemaArgNames(inputSchema: unknown): Set<string> {
  const props = (inputSchema as { properties?: unknown } | undefined)?.properties;
  return new Set(props && typeof props === "object" ? Object.keys(props) : []);
}

/**
 * Lints policy rules against the given tool schemas (arg names keyed by `<serverId>__<tool>`). Errors:
 * a rule parses but references an argument the tool's schema does not declare, or a rule for a tool no
 * server offers, or a declassify for an unknown tool. Warnings: a rule relying on a precision-mode
 * predicate (`from(...)`), which is bypassable (encoding/paraphrase) — Layer 1 still applies.
 *
 * `schemas` should be built from the pinned/live definitions; the caller re-lints on approve and on
 * lock updates (owner note #1). A tool with no schema entry is treated as "unknown tool".
 */
export function lintPolicy(config: Config, schemas: Map<string, Set<string>>): LintIssue[] {
  const issues: LintIssue[] = [];
  let engine: PolicyEngine;
  try {
    engine = new PolicyEngine(config);
  } catch (err) {
    issues.push({ level: 'error', where: 'policy', message: err instanceof CelError ? err.message : String(err) });
    return issues;
  }

  const argRefs = engine.argRefsByTool();
  for (const [exposed, refs] of argRefs) {
    const known = schemas.get(exposed);
    if (!known) {
      issues.push({ level: 'error', where: exposed, message: 'policy rules target a tool that no configured server offers (or that is not pinned)' });
      continue;
    }
    for (const arg of refs) {
      if (!known.has(arg)) issues.push({ level: 'error', where: exposed, message: `rule references argument '${arg}', which the tool's input schema does not declare` });
    }
  }

  // Precision-mode warnings: any rule source that calls a bypassable predicate.
  for (const [serverId, server] of Object.entries(config.servers)) {
    for (const [toolName, cls] of Object.entries(server.tools)) {
      for (const rule of cls.rules ?? []) {
        const src = rule.deny ?? rule.ask ?? rule.allow ?? '';
        for (const fn of PRECISION_FUNCTIONS) {
          if (new RegExp(`\\b${fn}\\s*\\(`).test(src)) {
            issues.push({ level: 'warning', where: `${serverId}.${toolName}`, message: `rule uses ${fn}(): precision-mode, bypassable by encoding/paraphrase — a missing match does not prove no flow (Layer 1 still applies)` });
          }
        }
      }
    }
  }

  for (const d of engine.declassifyRules) {
    const exposed = d.tool.includes('__') ? d.tool : d.tool.replace('.', '__');
    if (!schemas.has(exposed)) issues.push({ level: 'error', where: `declassify:${d.id}`, message: `declassify targets unknown tool '${d.tool}'` });
  }

  return issues;
}
