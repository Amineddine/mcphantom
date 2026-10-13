import crypto from 'node:crypto';
import { findSecrets } from '../secrets/detectors.js';
import { normalize } from '../text/normalize.js';

export { fold, normalize } from '../text/normalize.js';

export type IdentifierKind = 'secret' | 'url' | 'email' | 'token';

export interface Identifier {
  kind: IdentifierKind;
  /** SHA-256 of the raw value and of its normalized form. Plaintext is not retained. */
  rawHash: string;
  normHash: string;
  /** Detector rule for secrets. */
  rule?: string;
}

const URL_RE = /\bhttps?:\/\/[^\s"'<>()[\]{}`\\]{3,2048}/gi;
const EMAIL_RE = /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,8}\.[A-Za-z]{2,24}\b/g;
const TOKEN_RE = /[A-Za-z0-9_\-+/=]{24,512}/g;

export function sha(s: string): string {
  return crypto.createHash('sha256').update(s).digest('hex');
}

function ident(kind: IdentifierKind, value: string, rule?: string): Identifier {
  const id: Identifier = { kind, rawHash: sha(value), normHash: sha(normalize(value)) };
  if (rule) id.rule = rule;
  return id;
}

/** Shannon entropy in bits per character. */
export function entropy(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** A random-looking token: high entropy and a mix of character classes (not a word or a number). */
function isHighEntropyToken(t: string): boolean {
  const classes = Number(/[a-z]/.test(t)) + Number(/[A-Z]/.test(t)) + Number(/[0-9]/.test(t));
  return classes >= 2 && entropy(t) >= 3.5;
}

/**
 * High-entropy identifiers in a text: the things an exfiltration must reproduce exactly (DESIGN.md §2,
 * "core insight") — secrets, destinations (URLs, e-mail addresses) and long random tokens.
 */
export function extractIdentifiers(text: string): Identifier[] {
  const out: Identifier[] = [];
  for (const m of findSecrets(text)) out.push(ident('secret', text.slice(m.start, m.end), m.rule));
  for (const m of text.matchAll(URL_RE)) out.push(ident('url', m[0].replace(/[.,;:!?]+$/, '')));
  for (const m of text.matchAll(EMAIL_RE)) out.push(ident('email', m[0]));
  for (const m of text.matchAll(TOKEN_RE)) if (isHighEntropyToken(m[0])) out.push(ident('token', m[0]));
  return out;
}

export interface Leaf {
  path: string;
  value: string;
}

/** String leaves of a JSON value with their paths (numbers of 6+ digits count: PINs, account ids). */
export function leaves(v: unknown, path = '$', out: Leaf[] = [], depth = 0): Leaf[] {
  if (depth > 32) return out;
  if (typeof v === 'string') out.push({ path, value: v });
  else if (typeof v === 'number' && Number.isFinite(v) && Math.abs(v) >= 100_000) out.push({ path, value: String(v) });
  else if (Array.isArray(v)) v.forEach((x, i) => leaves(x, `${path}[${i}]`, out, depth + 1));
  else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) leaves(x, `${path}.${k}`, out, depth + 1);
  return out;
}

/**
 * Text a tool result puts into the model's context: text content, embedded resource text, resource
 * link URIs, and every string in structuredContent. Images and audio carry no extractable text here;
 * they are labeled by source only (documented limitation).
 */
export function resultTexts(result: unknown): string[] {
  const out: string[] = [];
  const r = result as { content?: unknown[]; structuredContent?: unknown; contents?: unknown[]; messages?: unknown[] };
  const fromBlock = (b: unknown): void => {
    if (!b || typeof b !== 'object') return;
    const block = b as { type?: string; text?: unknown; uri?: unknown; resource?: { text?: unknown; uri?: unknown } };
    if (typeof block.text === 'string') out.push(block.text);
    if (block.type === 'resource_link' && typeof block.uri === 'string') out.push(block.uri);
    if (block.resource && typeof block.resource.text === 'string') out.push(block.resource.text);
  };
  for (const b of r.content ?? []) fromBlock(b);
  for (const b of r.contents ?? []) fromBlock(b); // resources/read
  for (const m of r.messages ?? []) fromBlock((m as { content?: unknown }).content); // prompts/get
  if (r.structuredContent !== undefined) for (const l of leaves(r.structuredContent)) out.push(l.value);
  return out;
}
