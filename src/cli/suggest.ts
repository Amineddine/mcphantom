import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import type { Classification } from '../config/schema.js';
import { DEFAULT_CLASSIFICATION } from '../taint/engine.js';

/**
 * A classification suggestion for one tool during `init`. The secure default (egress / untrusted /
 * internal) always applies unless overridden. Suggestions are derived from the server's own
 * annotations and the tool name, so they are **server-claimed** — the server could lie. A suggestion
 * is therefore only applied automatically when it is at least as strict as the secure default
 * (`tighten`/`match`); a suggestion that would *loosen* the default (e.g. trusting a tool's output, or
 * downgrading egress to read) is marked `loosen` and never applied unless the user explicitly accepts
 * it. The UI shows the provenance ("server-claimed") on every annotation-derived suggestion.
 */
export interface Suggestion {
  tool: string;
  classification: Classification;
  /** `tighten`/`match` are safe to auto-apply; `loosen` needs explicit consent. */
  relation: 'tighten' | 'match' | 'loosen';
  /** Human-readable basis, flagged server-claimed when it comes from annotations. */
  basis: string;
  serverClaimed: boolean;
}

const READ_NAME = /\b(get|list|read|fetch|search|query|find|lookup|view|show|describe|status|stats)\b/i;
const EGRESS_NAME = /\b(send|post|email|upload|publish|notify|webhook|tweet|message|dispatch|deliver|sync|push)\b/i;
const EXEC_NAME = /\b(exec|run|shell|eval|spawn|command|bash|sh|python|script)\b/i;
const UNTRUSTED_NAME = /\b(fetch|browse|web|search|read_email|inbox|rss|feed|scrape|crawl)\b/i;

/**
 * Proposes a classification for a tool. Confidentiality is never auto-lowered. Effect/integrity
 * suggestions that are stricter than the default stand; looser ones are returned with `loosen`.
 */
export function suggestClassification(tool: Tool): Suggestion {
  const ann = (tool.annotations ?? {}) as { readOnlyHint?: unknown; destructiveHint?: unknown; openWorldHint?: unknown };
  // Tool names use `_`/`-` as separators; `\b` does not split on `_`, so normalise to spaces first.
  const name = tool.name.replace(/[_-]+/g, ' ');
  const basis: string[] = [];
  let serverClaimed = false;

  // Effect.
  let effect: Classification['effect'] = DEFAULT_CLASSIFICATION.effect; // egress (secure default)
  if (EXEC_NAME.test(name)) {
    effect = 'exec';
    basis.push(`name suggests exec`);
  } else if (EGRESS_NAME.test(name)) {
    effect = 'egress';
    basis.push('name suggests egress');
  } else if (ann.readOnlyHint === true) {
    effect = 'read';
    basis.push('annotation readOnlyHint=true');
    serverClaimed = true;
  } else if (READ_NAME.test(name)) {
    effect = 'read';
    basis.push('name suggests read');
  }

  // Integrity: untrusted if the tool pulls from the open world; else keep the untrusted default.
  let integrity: Classification['integrity'] = DEFAULT_CLASSIFICATION.integrity; // untrusted
  if (ann.openWorldHint === true || UNTRUSTED_NAME.test(name)) {
    integrity = 'untrusted';
    basis.push(ann.openWorldHint === true ? 'annotation openWorldHint=true' : 'name suggests open-world input');
    if (ann.openWorldHint === true) serverClaimed = true;
  }

  const classification: Classification = { effect, integrity };
  const relation = classifyRelation(classification);
  return { tool: tool.name, classification, relation, basis: basis.join('; ') || 'secure default', serverClaimed };
}

/** Whether a suggestion is stricter than, equal to, or looser than the secure default. */
function classifyRelation(c: Classification): Suggestion['relation'] {
  const effectRank: Record<NonNullable<Classification['effect']>, number> = { read: 0, write: 1, egress: 2, exec: 3 };
  const def = DEFAULT_CLASSIFICATION;
  // "Looser" = grants more capability or more trust than the default: a lower effect rank (read < egress)
  // means the tool is treated as less dangerous (looser), and trusted < untrusted means more trust (looser).
  const loosensEffect = c.effect !== undefined && effectRank[c.effect] < effectRank[def.effect];
  const loosensIntegrity = c.integrity === 'trusted' && def.integrity === 'untrusted';
  if (loosensEffect || loosensIntegrity) return 'loosen';
  const tightens = (c.effect !== undefined && effectRank[c.effect] > effectRank[def.effect]) || false;
  return tightens ? 'tighten' : 'match';
}

/** Merges accepted suggestions into a parsed profile doc's per-tool classification (pure). */
export function applySuggestions(
  profile: { servers: Record<string, { tools?: Record<string, Record<string, unknown>> }> },
  byServer: Map<string, Suggestion[]>,
  acceptLoose: boolean,
): { applied: number; skippedLoose: string[] } {
  let applied = 0;
  const skippedLoose: string[] = [];
  for (const [serverId, suggestions] of byServer) {
    const server = profile.servers[serverId];
    if (!server) continue;
    for (const s of suggestions) {
      if (s.relation === 'loosen' && !acceptLoose) {
        skippedLoose.push(`${serverId}__${s.tool}`);
        continue;
      }
      server.tools ??= {};
      server.tools[s.tool] = { ...server.tools[s.tool], ...s.classification };
      applied++;
    }
  }
  return { applied, skippedLoose };
}
