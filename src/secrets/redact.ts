import { findSecrets, SENSITIVE_KEY_RE, type SecretMatch } from './detectors.js';
import { possibleSecretsBeyond } from './entropy.js';

export interface RedactOptions {
  /** Exact values to redact wherever they occur (e.g. env values configured for upstream servers). */
  knownSecrets?: readonly string[];
  /** Total characters of string content examined; anything past the budget is dropped, not logged. */
  budgetChars?: number;
  maxDepth?: number;
  /** Also redact entropy-only possible secrets (`[REDACTED:possible-secret]`, or `possible-id` for
   *  identifier shapes (hex, UUIDs, digests, ids)). Default true (owner decision, Phase 6b). */
  entropy?: boolean;
}

const MIN_KNOWN_SECRET_LEN = 8;
const DEFAULT_BUDGET = 1_048_576;
const DEFAULT_DEPTH = 32;

export const TRUNCATED = '[TRUNCATED]';

/**
 * Redacts secrets from arbitrary JSON-like values before they are persisted.
 *
 * Order matters for safety: content is cut to the budget *before* detection, and everything past
 * the budget is dropped, so a secret straddling the cut can never be half-logged.
 */
export class Redactor {
  private readonly known: string[];
  private readonly budget: number;
  private readonly maxDepth: number;
  private readonly entropy: boolean;

  constructor(opts: RedactOptions = {}) {
    const known = new Set<string>();
    for (const s of opts.knownSecrets ?? []) {
      if (s.length < MIN_KNOWN_SECRET_LEN) continue;
      known.add(s);
      known.add(Buffer.from(s, 'utf8').toString('base64'));
      known.add(encodeURIComponent(s));
    }
    // Longest first so a secret that contains another is replaced whole.
    this.known = [...known].sort((a, b) => b.length - a.length);
    this.budget = opts.budgetChars ?? DEFAULT_BUDGET;
    this.maxDepth = opts.maxDepth ?? DEFAULT_DEPTH;
    this.entropy = opts.entropy ?? true;
  }

  redactString(text: string): string {
    let s = text;
    for (const k of this.known) {
      if (s.includes(k)) s = s.split(k).join('[REDACTED:configured-secret]');
    }
    const matches: SecretMatch[] = findSecrets(s);
    if (this.entropy) {
      for (const p of possibleSecretsBeyond(s, matches)) matches.push({ rule: p.shape === 'id' ? 'possible-id' : 'possible-secret', start: p.start, end: p.end });
    }
    if (matches.length === 0) return s;
    matches.sort((a, b) => a.start - b.start || b.end - a.end);
    let out = '';
    let pos = 0;
    let i = 0;
    while (i < matches.length) {
      const m = matches[i];
      if (!m) break;
      let end = m.end;
      const rules = new Set([m.rule]);
      let j = i + 1;
      for (let n = matches[j]; n && n.start < end; n = matches[++j]) {
        end = Math.max(end, n.end);
        rules.add(n.rule);
      }
      if (m.start >= pos) {
        out += s.slice(pos, m.start) + `[REDACTED:${[...rules].join(',')}]`;
        pos = end;
      } else if (end > pos) {
        out += `[REDACTED:${[...rules].join(',')}]`;
        pos = end;
      }
      i = j;
    }
    return out + s.slice(pos);
  }

  /** Returns a redacted deep copy. Never mutates the input. */
  redactValue(value: unknown): unknown {
    const state = { remaining: this.budget };
    return this.walk(value, 0, state);
  }

  private walk(v: unknown, depth: number, state: { remaining: number }): unknown {
    if (state.remaining <= 0) return TRUNCATED;
    if (typeof v === 'string') {
      const cut = v.length > state.remaining ? safeCut(v, state.remaining) : v;
      state.remaining -= cut.length;
      const red = this.redactString(cut);
      return cut.length < v.length ? red + TRUNCATED : red;
    }
    if (v === null || typeof v !== 'object') return v;
    if (depth >= this.maxDepth) return TRUNCATED;
    if (Array.isArray(v)) {
      const out: unknown[] = [];
      for (const item of v) {
        if (state.remaining <= 0) {
          out.push(TRUNCATED);
          break;
        }
        out.push(this.walk(item, depth + 1, state));
      }
      return out;
    }
    const out: Record<string, unknown> = {};
    for (const [k, item] of Object.entries(v as Record<string, unknown>)) {
      if (state.remaining <= 0) {
        out[TRUNCATED] = true;
        break;
      }
      state.remaining -= k.length;
      const key = this.redactString(k);
      out[key] = SENSITIVE_KEY_RE.test(k) && item !== null && item !== '' ? '[REDACTED:sensitive-key]' : this.walk(item, depth + 1, state);
    }
    return out;
  }
}

const DELIM_RE = /[\s"',;]/;
const BACKTRACK = 4096;

/**
 * Cuts `text` to at most `limit` chars without leaving a partial token at the end: a secret cut in
 * half no longer matches any detector, so the partial token is dropped instead of logged.
 */
export function safeCut(text: string, limit: number): string {
  if (text.length <= limit) return text;
  const cut = text.slice(0, limit);
  for (let i = cut.length - 1; i >= Math.max(0, cut.length - BACKTRACK); i--) {
    if (DELIM_RE.test(cut.charAt(i))) return cut.slice(0, i + 1);
  }
  return cut.slice(0, Math.max(0, cut.length - BACKTRACK));
}
