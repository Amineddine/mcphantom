import { resolve } from 'node:path';
import type { Classification, Config } from '../config/schema.js';
import { hasOutsideTarget } from './egress.js';
import { BOTTOM, canExfiltrate, join, type Effect, type Label } from './labels.js';
import { ProvenanceIndex, type EvictionNotice, type Evidence, type OutputRef } from './provenance.js';
import { resultTexts } from './text.js';

export interface ResolvedClassification {
  effect: Effect;
  integrity: Label['integrity'];
  confidentiality: Label['confidentiality'];
  workspace: string | undefined;
  pathArgs: readonly string[] | undefined;
  /** Which fields came from explicit configuration (for the trace), vs. the secure default. */
  explicit: (keyof Classification)[];
}

/** Secure global default for anything the user has not classified (DESIGN.md §3.4). */
export const DEFAULT_CLASSIFICATION: Omit<ResolvedClassification, 'explicit' | 'workspace' | 'pathArgs'> = { effect: 'egress', integrity: 'untrusted', confidentiality: 'internal' };

export function classify(config: Config, serverId: string, name: string | undefined): ResolvedClassification {
  const server = config.servers[serverId];
  const tool = name !== undefined ? server?.tools[name] : undefined;
  const out: ResolvedClassification = { ...DEFAULT_CLASSIFICATION, workspace: undefined, pathArgs: undefined, explicit: [] };
  for (const key of ['effect', 'integrity', 'confidentiality'] as const) {
    const v = tool?.[key] ?? server?.defaults[key];
    if (v !== undefined) {
      (out as unknown as Record<string, unknown>)[key] = v;
      out.explicit.push(key);
    }
  }
  const ws = tool?.workspace ?? server?.defaults.workspace;
  if (ws !== undefined) {
    out.workspace = server?.type === 'stdio' && server.cwd !== undefined ? resolve(server.cwd, ws) : ws;
  }
  out.pathArgs = tool?.path_args ?? server?.defaults.path_args;
  return out;
}

export interface IngestResult {
  ref: OutputRef;
  secretsDetected: string[];
  identifiers: number;
  evictions: EvictionNotice[];
  contextBefore: Label;
  contextAfter: Label;
}

export type Verdict = 'allow' | 'deny';

export interface Decision {
  id: string;
  verdict: Verdict;
  /** Set when an invariant matched; in audit mode the verdict stays `allow`. */
  rule?: 'trifecta';
  enforced: boolean;
  server: string;
  tool: string;
  effect: Effect;
  context: Label;
  /** Outputs that made the context untrusted / secret: the Layer-1 explanation. */
  untrustedSources: OutputRef[];
  secretSources: OutputRef[];
  /** Layer-2 attribution of this call's arguments. Explanation only; never grounds an allow. */
  evidence: Evidence[];
  /** True if provenance text was evicted for outputs that carried a non-bottom label, so the absence
   *  of evidence may be an artefact of eviction. */
  attributionDegraded: boolean;
  reason: string;
}

/**
 * Per-session taint state. Owns the context label (Layer 1) and the provenance index (Layer 2).
 * One instance per downstream connection: MCPhantom cannot see conversation boundaries inside a
 * client, so the label accumulates for the life of the connection (documented over-tainting).
 */
export class TaintEngine {
  private readonly config: Config;
  private readonly index: ProvenanceIndex;
  private seq = 0;
  private decisions = 0;
  context: Label = BOTTOM;
  private readonly untrustedSources: OutputRef[] = [];
  private readonly secretSources: OutputRef[] = [];
  private degraded = false;

  constructor(config: Config) {
    this.config = config;
    this.index = new ProvenanceIndex({ maxTierABytes: config.taint.max_index_mb * 1024 * 1024 });
  }

  /** Records content entering the model's context and raises the context label. */
  ingest(kind: OutputRef['kind'], serverId: string, source: string, name: string | undefined, payload: unknown): IngestResult {
    const cls = classify(this.config, serverId, name);
    const texts = resultTexts(payload);
    const id = `o${++this.seq}`;
    // The label is computed before indexing so the ref stored in the index is final.
    const provisional: OutputRef = { id, seq: this.seq, server: serverId, source, kind, label: { integrity: cls.integrity, confidentiality: cls.confidentiality } };
    const added = this.index.add(provisional, texts);
    if (added.secrets.length > 0) provisional.label.confidentiality = 'secret';
    const before = this.context;
    this.context = join(this.context, provisional.label);
    if (provisional.label.integrity === 'untrusted') this.untrustedSources.push(provisional);
    if (provisional.label.confidentiality === 'secret') this.secretSources.push(provisional);
    for (const e of added.evictions) {
      if (e.output.label.integrity === 'untrusted' || e.output.label.confidentiality !== 'public') this.degraded = true;
    }
    return { ref: provisional, secretsDetected: added.secrets, identifiers: added.identifiers, evictions: added.evictions, contextBefore: before, contextAfter: this.context };
  }

  /** Decides a tools/call before it is forwarded. */
  decide(serverId: string, toolName: string, exposedName: string, args: unknown): Decision {
    const cls = classify(this.config, serverId, toolName);
    const tool = exposedName;
    const evidence = this.index.attribute(args);
    const id = `d${++this.decisions}`;
    // A `write` whose target leaves the declared workspace (remote URL, absolute path elsewhere, or a
    // `..` escape) is exfiltration in disguise, so it is treated as `egress` for the invariant.
    const effect: Effect = cls.effect === 'write' && hasOutsideTarget(args, cls.workspace, cls.pathArgs) ? 'egress' : cls.effect;
    const upgraded = effect !== cls.effect;
    const base = {
      id, server: serverId, tool, effect, context: { ...this.context },
      untrustedSources: [...this.untrustedSources], secretSources: [...this.secretSources],
      evidence, attributionDegraded: this.degraded,
    };
    const trifecta = canExfiltrate(effect) && this.context.integrity === 'untrusted' && this.context.confidentiality === 'secret';
    if (!trifecta) {
      return { ...base, verdict: 'allow', enforced: false, reason: allowReason(effect, this.context) };
    }
    const enforced = this.config.taint.trifecta === 'deny';
    const why = upgraded ? 'write to a target outside the declared workspace (treated as egress)' : `${effect} call`;
    return {
      ...base,
      verdict: enforced ? 'deny' : 'allow',
      rule: 'trifecta',
      enforced,
      reason:
        `${why} while the session holds untrusted content (${describe(this.untrustedSources)}) ` +
        `and secret data (${describe(this.secretSources)})${enforced ? '' : ' — audit mode, not blocked'}`,
    };
  }

  get indexStats() {
    return this.index.stats;
  }
}

function allowReason(effect: Effect, ctx: Label): string {
  if (!canExfiltrate(effect)) return `${effect} effect cannot exfiltrate`;
  if (ctx.integrity === 'trusted') return 'no untrusted content in context';
  return 'no secret data in context';
}

function describe(refs: OutputRef[]): string {
  const names = [...new Set(refs.map((r) => r.source))];
  return names.length <= 3 ? names.join(', ') : `${names.slice(0, 3).join(', ')} and ${names.length - 3} more`;
}
