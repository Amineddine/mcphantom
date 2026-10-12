import crypto from 'node:crypto';

/**
 * Canonical JSON serialization (RFC 8785 / JCS, the subset we need): object keys sorted by their
 * UTF-16 code-unit sequence, no insignificant whitespace, and JSON.stringify's own number and string
 * escaping (which matches JCS for the finite, already-parsed values MCP definitions contain). We never
 * see NaN/Infinity (they are not valid JSON), and integers from JSON parsing round-trip exactly.
 *
 * The point is a byte-for-byte stable encoding so the same tool definition always hashes the same,
 * regardless of key order or formatting from the upstream server.
 */
/** Depth cap so a hostile deeply-nested schema throws a clean, catchable error, not a stack overflow. */
const MAX_DEPTH = 200;

export function canonicalize(value: unknown): string {
  return encode(value, 0);
}

function encode(v: unknown, depth: number): string {
  if (depth > MAX_DEPTH) throw new Error(`cannot canonicalize: nesting deeper than ${MAX_DEPTH}`);
  if (v === null) return 'null';
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new Error('cannot canonicalize a non-finite number');
    return JSON.stringify(v);
  }
  if (typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map((x) => encode(x === undefined ? null : x, depth + 1)).join(',') + ']';
  if (typeof v === 'object') {
    const obj = v as Record<string, unknown>;
    const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort(compareCodeUnits);
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + encode(obj[k], depth + 1)).join(',') + '}';
  }
  // undefined / function / symbol at top level → treat as null (matches how they'd drop in JSON).
  return 'null';
}

/** Sort by UTF-16 code units, as JCS specifies (this is JavaScript's default string comparison). */
function compareCodeUnits(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export function sha256Hex(s: string): string {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

/** Stable SHA-256 fingerprint of a value's canonical form. */
export function fingerprint(value: unknown): string {
  return sha256Hex(canonicalize(value));
}
