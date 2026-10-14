import path from 'node:path';
import type { Paths } from '../config/paths.js';
import { SqliteStore, type StoredEvent } from '../store/store.js';
import type { Decision } from '../taint/engine.js';
import { silentLogger } from '../util/log.js';

export interface TraceOptions {
  dataDir?: string | undefined;
  sessionId?: string | undefined;
  last: boolean;
  json: boolean;
  paths: Paths;
}

/**
 * Renders the taint trace for a session: the sequence of context-raising ingests and the decisions,
 * with the Layer-1 sources and Layer-2 evidence behind each block. Read-only; opens the event DB
 * without taking the permission-fixing path a running gateway would.
 */
export function runTrace(opts: TraceOptions, out: (s: string) => void): number {
  const dataDir = opts.dataDir ? path.resolve(opts.dataDir) : opts.paths.dataDir;
  const store = new SqliteStore({
    dataDir, payloads: 'redacted', maxPayloadBytes: 65_536, retentionDays: 36_500, retentionMaxMb: 1_000_000,
    knownSecrets: [], insecurePermissions: 'warn', logger: silentLogger,
  });
  try {
    let sessionId = opts.sessionId;
    if (!sessionId) {
      const sessions = store.sessions(1);
      if (sessions.length === 0) {
        out('No sessions recorded yet.');
        return 1;
      }
      sessionId = sessions[0]?.id;
    }
    const events = store.events({ ...(sessionId ? { sessionId } : {}), limit: 100_000 }).filter((e) => e.kind === 'taint' || e.kind === 'decision' || e.kind === 'eviction');
    if (opts.json) {
      out(JSON.stringify(events.map((e) => ({ ...e, payload: e.payload ? (JSON.parse(e.payload) as unknown) : null })), null, 2));
      return 0;
    }
    if (opts.last) {
      const lastDecision = [...events].reverse().find((e) => e.kind === 'decision');
      if (!lastDecision) {
        out(`No taint decisions in session ${sessionId ?? '(unknown)'}.`);
        return 1;
      }
      renderDecision(lastDecision, out);
      return 0;
    }
    out(`session ${sessionId ?? '(unknown)'} — ${events.length} taint event(s)\n`);
    for (const e of events) {
      if (e.kind === 'taint') renderIngest(e, out);
      else if (e.kind === 'decision') renderDecision(e, out);
      else out(`  · evicted provenance for ${e.name ?? '?'} (memory budget)`);
    }
    return 0;
  } finally {
    store.close();
  }
}

function parsePayload(e: StoredEvent): unknown {
  return e.payload ? JSON.parse(e.payload) : undefined;
}

function renderIngest(e: StoredEvent, out: (s: string) => void): void {
  const p = parsePayload(e) as { contextAfter: { integrity: string; confidentiality: string }; secretsDetected: string[]; possibleSecrets?: { random: number; hash: number } } | undefined;
  if (!p) return;
  const secrets = p.secretsDetected.length ? ` secrets:[${p.secretsDetected.join(',')}]` : '';
  const ps = p.possibleSecrets;
  const possible = ps && ps.random + ps.hash > 0 ? ` possible secrets: ${ps.random} random, ${ps.hash} hash-shaped` : '';
  out(`  ⇩ ${e.name ?? '?'} → context ${p.contextAfter.integrity}/${p.contextAfter.confidentiality}${secrets}${possible}`);
}

function renderDecision(e: StoredEvent, out: (s: string) => void): void {
  const d = parsePayload(e) as Decision | undefined;
  if (!d) return;
  const mark = d.verdict === 'deny' ? 'DENY' : d.verdict === 'ask' ? 'ASK' : d.rule ? 'FLAG' : 'allow';
  out(`\n  [${mark}] ${d.tool}  (decision ${d.id})`);
  out(`    context: ${d.context.integrity}/${d.context.confidentiality}; effect: ${d.effect}`);
  out(`    reason:  ${d.reason}`);
  if (d.untrustedSources.length) out(`    untrusted from: ${[...new Set(d.untrustedSources.map((s) => s.source))].join(', ')}`);
  if (d.secretSources.length) out(`    secret from:    ${[...new Set(d.secretSources.map((s) => s.source))].join(', ')}`);
  for (const ev of d.evidence) {
    const how = [
      ev.matcher,
      ev.rule,
      ev.chain ? `decoded ${ev.chain.join(' → ')}` : undefined,
      ev.outputChain ? `encoded in output as ${ev.outputChain.join(' → ')}` : undefined,
      ev.score !== undefined ? `score ${ev.score}` : undefined,
      ev.priorCalls !== undefined ? `joined with ${ev.priorCalls} earlier call(s)` : undefined,
    ].filter((x) => x !== undefined).join(', ');
    out(`    evidence: ${ev.argPath} ${ev.kind} (${how}) ← ${ev.output.source}`);
  }
  if (d.attributionDegraded) out('    note: attribution hit a bound (memory budget, size or decode limit); evidence may be incomplete (Layer 1 still applied)');
}
