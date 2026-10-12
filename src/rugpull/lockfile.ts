import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { ensurePrivateDir, restrictFile, writePrivateFile } from '../security/fileperms.js';
import { canonicalize, sha256Hex } from './canonical.js';

/** One server's pinned, approved definitions. Values are canonical-JSON SHA-256 fingerprints. */
export interface ServerPins {
  instructions: string | null;
  tools: Record<string, string>;
  prompts: Record<string, string>;
  approvedAt: string;
}

export interface LockfileData {
  version: 1;
  servers: Record<string, ServerPins>;
}

export interface Lockfile {
  path: string;
  data: LockfileData;
  /** HMAC verification outcome of what was read from disk. */
  integrity: 'ok' | 'empty' | 'missing-key' | 'bad-signature' | 'malformed';
}

const LOCK_VERSION = 1 as const;

export function lockPathFor(configPath: string): string {
  return configPath.replace(/\.(ya?ml|json)$/i, '') + '.lock';
}

/**
 * Loads and verifies a lockfile. A present lockfile whose HMAC does not match the key is reported as
 * `bad-signature` (tampering or a different machine/user); the caller decides whether to refuse. A
 * missing lockfile yields `empty` data with integrity `empty` (nothing is pinned yet).
 */
export function loadLockfile(configPath: string, keyDir: string): Lockfile {
  const p = lockPathFor(configPath);
  if (!fs.existsSync(p)) return { path: p, data: { version: LOCK_VERSION, servers: {} }, integrity: 'empty' };
  let raw: string;
  try {
    raw = fs.readFileSync(p, 'utf8');
  } catch {
    return { path: p, data: { version: LOCK_VERSION, servers: {} }, integrity: 'malformed' };
  }
  let parsed: { version?: unknown; servers?: unknown; hmac?: unknown };
  try {
    parsed = JSON.parse(raw) as typeof parsed;
  } catch {
    return { path: p, data: { version: LOCK_VERSION, servers: {} }, integrity: 'malformed' };
  }
  if (parsed.version !== LOCK_VERSION || typeof parsed.servers !== 'object' || parsed.servers === null || typeof parsed.hmac !== 'string') {
    return { path: p, data: { version: LOCK_VERSION, servers: {} }, integrity: 'malformed' };
  }
  const key = readKeyIfPresent(keyDir);
  if (!key) return { path: p, data: { version: LOCK_VERSION, servers: parsed.servers as Record<string, ServerPins> }, integrity: 'missing-key' };
  const expected = hmac(key, parsed.servers);
  const ok = safeEqualHex(expected, parsed.hmac);
  return {
    path: p,
    data: { version: LOCK_VERSION, servers: parsed.servers as Record<string, ServerPins> },
    integrity: ok ? 'ok' : 'bad-signature',
  };
}

/** Writes the lockfile atomically, owner-only, signed with the (created-if-absent) key. */
export function saveLockfile(configPath: string, keyDir: string, data: LockfileData): string {
  const p = lockPathFor(configPath);
  const key = ensureKey(keyDir);
  const body = { version: LOCK_VERSION, servers: data.servers, hmac: hmac(key, data.servers) };
  writePrivateFile(p, JSON.stringify(body, null, 2) + '\n');
  return p;
}

// --------------------------------------------------------------------------------------------------
// HMAC key management: an owner-only key file. See DESIGN.md §1 for the precise threat scope.

const KEY_FILE = 'hmac.key';

function keyPath(keyDir: string): string {
  return path.join(keyDir, KEY_FILE);
}

function readKeyIfPresent(keyDir: string): Buffer | undefined {
  const p = keyPath(keyDir);
  if (!fs.existsSync(p)) return undefined;
  const hex = fs.readFileSync(p, 'utf8').trim();
  return /^[0-9a-f]{64}$/.test(hex) ? Buffer.from(hex, 'hex') : undefined;
}

export function ensureKey(keyDir: string): Buffer {
  const existing = readKeyIfPresent(keyDir);
  if (existing) return existing;
  ensurePrivateDir(keyDir);
  const key = crypto.randomBytes(32);
  const p = keyPath(keyDir);
  // Create exclusively so we never overwrite a key another concurrent process just wrote.
  try {
    writePrivateFile(p, key.toString('hex') + '\n');
  } catch {
    const raced = readKeyIfPresent(keyDir);
    if (raced) return raced;
    throw new Error(`could not create HMAC key at ${p}`);
  }
  restrictFile(p);
  return readKeyIfPresent(keyDir) ?? key;
}

function hmac(key: Buffer, servers: unknown): string {
  return crypto.createHmac('sha256', key).update(canonicalize(servers), 'utf8').digest('hex');
}

function safeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length || !/^[0-9a-f]+$/.test(b)) return false;
  return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

export { sha256Hex };
