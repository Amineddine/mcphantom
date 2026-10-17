import { resolve } from 'node:path';
import type { Classification, Config } from '../config/schema.js';
import { hasOutsideTarget } from './egress.js';
import { BOTTOM, canExfiltrate, confAtLeast, join, type Confidentiality, type Effect, type Label } from './labels.js';
import { ProvenanceIndex, type DegradeCause, type EvictionNotice, type Evidence, type Matcher, type OutputRef } from './provenance.js';
import { describeSources, SourceLog, type SessionSources } from './sources.js';
import { leaves, resultTexts } from './text.js';
import { PolicyEngine, type PolicyOutcome } from '../policy/engine.js';
import { findSecrets } from '../secrets/detectors.js';
import { MAX_ENTROPY_SCAN, possibleSecretsBeyond } from '../secrets/entropy.js';
import { secretRuleIn } from '../secrets/in-value.js';

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
  /** Entropy-only "possible secrets" (no known format), by shape. Values are never recorded. Whether
   *  `random` ones raised the label is `secrets.entropy.on_hit`; `id` (identifier-shaped) ones never do. */
  possibleSecrets: { random: number; id: number };
  identifiers: number;
  evictions: EvictionNotice[];
  /** Decoding of this output was cut short by a bound; encoded identifiers past it are not indexed. */
  decodeTruncated: boolean;
  contextBefore: Label;
  contextAfter: Label;
}

/** `ask`: the call may proceed only after the user explicitly confirms it (elicitation); if the user
 *  cannot be asked, the gateway denies. Never an implicit allow. */
export type Verdict = 'allow' | 'deny' | 'ask';

export interface Decision {
  id: string;
  verdict: Verdict;
  /** Set when an invariant or policy rule drove the verdict; in audit mode the verdict stays `allow`. */
  rule?: 'trifecta' | 'policy' | 'may_receive';
  enforced: boolean;
  /** Policy rule matches and errors for this call (undefined if the tool has no rules). */
  policy?: PolicyOutcome;
  server: string;
  tool: string;
  effect: Effect;
  context: Label;
  /** The Layer-1 explanation, bounded: the outputs that raised the context label, and a summary of the
   *  session's untrusted and secret outputs (each is logged once, as its `taint` event). */
  sources: SessionSources;
  /** Layer-2 attribution of this call's arguments. Explanation only; never grounds an allow. */
  evidence: Evidence[];
  /** True if attribution was bounded for this call (size caps, decode budget) or for an earlier
   *  output carrying a non-bottom label (eviction, decode cap), so the absence of evidence may be an
   *  artefact of a bound. */
  attributionDegraded: boolean;
  /** Which bounds degraded it: this call's (`DegradeCause`) and the session's — `evicted` (a labelled
   *  output's index entries were dropped) or `output-decode` (an output was decoded only in part). */
  degradedBy: (DegradeCause | 'evicted' | 'output-decode')[];
  reason: string;
}

/** Switches for the ablation benchmark (`bench:ablations`); never set by the gateway. */
export interface Ablation {
  /** Layer-2 matchers that run (default: all). */
  matchers?: ReadonlySet<Matcher>;
  /** The `may_receive` clear-text credential search over arguments (default: on). */
  argCredentials?: boolean;
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
  /** Bounded whatever the session's length; its bytes count against the index budget. */
  private readonly sources = new SourceLog();
  private degraded = false;
  /** Highest confidentiality among outputs attribution lost track of (evicted, or decoded only in
   *  part); `public` while none. Read by the `may_receive` bound (R6b-1, Phase 7). */
  private degradedConf: Confidentiality = 'public';
  private readonly sessionCauses = new Set<'evicted' | 'output-decode'>();
  private readonly policy: PolicyEngine | undefined;

  private readonly argCredentials: boolean;

  /** `ablation` is for the ablation benchmark only (Phase 7 item 4): it is not part of the configuration
   *  and nothing in the gateway passes it. Omitted, every matcher and check runs. */
  constructor(config: Config, policy?: PolicyEngine, ablation: Ablation = {}) {
    this.config = config;
    this.index = new ProvenanceIndex({ maxTierABytes: config.taint.max_index_mb * 1024 * 1024, ...(ablation.matchers ? { matchers: ablation.matchers } : {}) });
    this.policy = policy;
    this.argCredentials = ablation.argCredentials ?? true;
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
    const possible = this.possibleSecrets(texts);
    const onHit = this.config.secrets.entropy.on_hit;
    if (possible.random > 0 && onHit !== 'record') {
      // Owner decision: entropy alone never escalates unless configured to; `internal` only raises.
      provisional.label.confidentiality = join({ integrity: 'trusted', confidentiality: onHit }, provisional.label).confidentiality;
    }
    const before = this.context;
    this.context = join(this.context, provisional.label);
    this.sources.add(provisional, before, this.context);
    this.index.chargeExternal(this.sources.bytes);
    const labelled = (l: Label): boolean => l.integrity === 'untrusted' || l.confidentiality !== 'public';
    for (const e of added.evictions) if (labelled(e.output.label)) this.loseTrack(e.output.label, 'evicted');
    if (added.decodeTruncated && labelled(provisional.label)) this.loseTrack(provisional.label, 'output-decode');
    return {
      ref: provisional, secretsDetected: added.secrets, possibleSecrets: possible, identifiers: added.identifiers, evictions: added.evictions,
      decodeTruncated: added.decodeTruncated, contextBefore: before, contextAfter: this.context,
    };
  }

  private loseTrack(l: Label, cause: 'evicted' | 'output-decode'): void {
    this.degraded = true;
    this.sessionCauses.add(cause);
    this.degradedConf = join({ integrity: 'trusted', confidentiality: this.degradedConf }, l).confidentiality;
  }

  private possibleSecrets(texts: string[]): { random: number; id: number } {
    const out = { random: 0, id: 0 };
    if (!this.config.secrets.entropy.enabled) return out;
    const raw = texts.join('\n').slice(0, MAX_ENTROPY_SCAN);
    for (const p of possibleSecretsBeyond(raw, findSecrets(raw))) out[p.shape]++;
    return out;
  }

  /** Decides a tools/call before it is forwarded. */
  decide(serverId: string, toolName: string, exposedName: string, args: unknown): Decision {
    const cls = classify(this.config, serverId, toolName);
    const tool = exposedName;
    const attribution = this.index.attributeCall(args, { sink: exposedName, now: this.now() });
    const id = `d${++this.decisions}`;
    // A `write` whose target leaves the declared workspace (remote URL, absolute path elsewhere, or a
    // `..` escape) is exfiltration in disguise, so it is treated as `egress` for the invariant.
    const effect: Effect = cls.effect === 'write' && hasOutsideTarget(args, cls.workspace, cls.pathArgs) ? 'egress' : cls.effect;
    const upgraded = effect !== cls.effect;
    const policy = this.policy?.evaluate({ serverId, toolName, args, context: this.context, provenanceOf: (v, deterministic) => this.provenanceOf(v, deterministic) });
    const base = {
      id, server: serverId, tool, effect, context: { ...this.context },
      sources: this.sources.snapshot(),
      evidence: attribution.evidence, attributionDegraded: this.degraded || attribution.degraded,
      degradedBy: [...attribution.degradedBy, ...this.sessionCauses],
      ...(policy ? { policy } : {}),
    };

    // 1. An explicit policy deny (or a fail-closed policy error) always wins.
    if (policy && (policy.effect === 'deny' || policy.errors.length > 0)) {
      const err = policy.errors[0];
      return { ...base, verdict: 'deny', rule: 'policy', enforced: true, reason: err ? `policy failed closed (${err.origin}): ${err.message}` : `denied by policy rule (${policy.matches.find((m) => m.effect === 'deny')?.origin ?? '?'})` };
    }

    // 2. The server's `may_receive` bound: every call sends its arguments to the server's operator.
    const bound = this.config.servers[serverId]?.may_receive;
    if (bound) {
      const why = this.mayReceiveViolation(serverId, bound, args, attribution.evidence, attribution.degradedBy);
      if (why) return { ...base, verdict: 'deny', rule: 'may_receive', enforced: true, reason: `server '${serverId}' may receive at most ${bound} data; ${why}` };
    }

    // 3. The trifecta invariant, unless a named declassify entry lifts it for this call.
    const trifecta = canExfiltrate(effect) && this.context.integrity === 'untrusted' && this.context.confidentiality === 'secret';
    if (trifecta && !policy?.declassified) {
      const enforced = this.config.taint.trifecta === 'deny';
      const why = upgraded ? 'write to a target outside the declared workspace (treated as egress)' : `${effect} call`;
      const reason =
        `${why} while the session holds untrusted content (${describeSources(base.sources.untrustedOutputs)}) ` +
        `and secret data (${describeSources(base.sources.secretOutputs)})${enforced ? '' : ' — audit mode, not blocked'}`;
      // Audit mode records the invariant but must not displace a policy `ask`: returning `allow` here
      // would silently skip an author-written confirmation (fail-open, found in 6b).
      if (!enforced && policy?.effect === 'ask') {
        return { ...base, verdict: 'ask', rule: 'policy', enforced: true, reason: `${askReason(policy)}; also: ${reason}` };
      }
      return { ...base, verdict: enforced ? 'deny' : 'allow', rule: 'trifecta', enforced, reason };
    }

    // 4. A policy `ask`.
    if (policy?.effect === 'ask') {
      return { ...base, verdict: 'ask', rule: 'policy', enforced: true, reason: askReason(policy) };
    }

    // 5. Allow (noting a lifted invariant when that is why we are here).
    const lifted = trifecta && policy?.declassified;
    return {
      ...base,
      verdict: 'allow',
      enforced: false,
      reason: lifted ? `trifecta lifted by declassify '${policy.declassified?.id}': ${policy.declassified?.reason}` : allowReason(effect, this.context),
    };
  }

  /**
   * Why sending `args` to `serverId` would exceed its `may_receive` bound, or undefined. Evidence mode:
   * an argument carries a credential (only `secret` data is known from content alone; every field is
   * searched in full in clear text and, over its first 32 KiB, decoded), or Layer 2 attributes it to an
   * output labelled above the bound — evidence may add restrictions (DESIGN.md §2, honesty rule), so every matcher counts here. Where
   * attribution could not look, the bound fails closed (R6b-1, Phase 7, owner option B): on this call's
   * bounds that can hide a credential, an identifier or a verbatim copy (not the fuzzy/cumulative ones,
   * which lose only edited copies and far-apart splits), and on earlier outputs it lost track of — in
   * both cases only if what it might have missed is above the bound. The reason names the bound and
   * the way out. Context mode adds the sound check on the context label.
   */
  private mayReceiveViolation(serverId: string, bound: Confidentiality, args: unknown, evidence: Evidence[], callDegradedBy: DegradeCause[]): string | undefined {
    const above = (c: Confidentiality): boolean => c !== bound && confAtLeast(c, bound);
    if (this.config.servers[serverId]?.may_receive_mode === 'context' && above(this.context.confidentiality)) {
      return `the session context is ${this.context.confidentiality} (may_receive_mode: context)`;
    }
    if (this.argCredentials && above('secret')) {
      for (const leaf of leaves(args)) {
        const rule = secretRuleIn(leaf.value);
        if (rule) return `argument ${leaf.path} carries a credential (${rule})`;
      }
    }
    const hit = evidence.find((e) => above(e.output.label.confidentiality));
    if (hit) return `argument ${hit.argPath} came from ${hit.output.source}, labelled ${hit.output.label.confidentiality} (${hit.matcher})`;
    const raise = `or raise may_receive for '${serverId}' if it may receive ${this.context.confidentiality} data`;
    // Attribution's per-call bounds were hit: it cannot say these arguments are clean. Only matters if
    // the session holds something above the bound at all.
    const hiding = callDegradedBy.filter((c) => c in CALL_BOUND);
    if (hiding.length > 0 && above(this.context.confidentiality)) {
      const what = hiding.map((c) => CALL_BOUND[c as keyof typeof CALL_BOUND]).join('; ');
      return `fail-closed: attribution could not check these arguments (${what}) and the session holds ${this.context.confidentiality} data. To send this, split it into smaller calls (fields ≤ 64 KiB, ≤ 512 fields, ≤ 128 KiB of text in all), ${raise}`;
    }
    // Attribution lost track of earlier outputs above the bound.
    if (above(this.degradedConf)) {
      const fix = this.sessionCauses.has('evicted') ? 'raise taint.max_index_mb (the provenance index evicted it), start a new session, ' : 'start a new session (an output over 128 KiB was decoded only in part), ';
      return `fail-closed: attribution lost track of ${this.degradedConf} data earlier in this session. To continue, ${fix}${raise}`;
    }
    return undefined;
  }

  /**
   * Records that a call was forwarded (allowed, or approved by the user), for the cumulative matcher.
   * The gateway calls this only for calls it actually sends; a denied call sent nothing.
   */
  sent(exposedName: string, args: unknown): void {
    this.index.recordSent(exposedName, args, this.now());
  }

  /** Clock for the cumulative window, injectable for tests. */
  now: () => number = () => Date.now();

  /** Integrity levels the provenance index attributes to a value — for the policy `from()` predicate. */
  provenanceOf(value: string, deterministic = false): Set<'trusted' | 'untrusted'> {
    const out = new Set<'trusted' | 'untrusted'>();
    for (const e of this.index.attribute({ v: value })) {
      if (deterministic && (e.matcher === 'fuzzy' || e.matcher === 'cumulative')) continue;
      out.add(e.output.label.integrity);
    }
    return out;
  }

  get indexStats() {
    return this.index.stats;
  }
}

/** Attribution bounds that can hide a credential, an identifier or a verbatim copy, as reported to the
 *  user when `may_receive` fails closed on them. */
const CALL_BOUND = {
  leaves: 'more than 512 argument fields',
  'leaf-size': 'an argument field over 64 KiB',
  'call-size': 'over 1 MiB of argument text',
  'decode-budget': 'over 128 KiB of argument text to decode',
  'decode-limit': 'an argument decodes into more variants than attribution follows',
} as const;

function askReason(policy: PolicyOutcome): string {
  return `policy requires user confirmation (${policy.matches.find((m) => m.effect === 'ask')?.origin ?? '?'})`;
}

function allowReason(effect: Effect, ctx: Label): string {
  if (!canExfiltrate(effect)) return `${effect} effect cannot exfiltrate`;
  if (ctx.integrity === 'trusted') return 'no untrusted content in context';
  return 'no secret data in context';
}

