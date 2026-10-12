import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { SERVER_ID_RE } from '../config/schema.js';

/** MCP clients whose config `mcphantom init` can rewrite. All use the `mcpServers` object format. */
export type ClientKind = 'claude-code' | 'claude-desktop' | 'cursor' | 'cursor-project' | 'file';

export interface ClientTarget {
  kind: ClientKind;
  file: string;
  /** Suggested profile name. */
  profile: string;
  label: string;
}

export function knownClientTargets(cwd: string, platform: NodeJS.Platform = process.platform, env: NodeJS.ProcessEnv = process.env): ClientTarget[] {
  const home = os.homedir();
  const desktop =
    platform === 'win32'
      ? path.join(env.APPDATA ?? path.join(home, 'AppData', 'Roaming'), 'Claude', 'claude_desktop_config.json')
      : platform === 'darwin'
        ? path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')
        : path.join(env.XDG_CONFIG_HOME ?? path.join(home, '.config'), 'Claude', 'claude_desktop_config.json');
  return [
    { kind: 'claude-code', file: path.join(cwd, '.mcp.json'), profile: projectProfile('cc', cwd), label: 'Claude Code (project .mcp.json)' },
    { kind: 'claude-desktop', file: desktop, profile: 'claude-desktop', label: 'Claude Desktop' },
    { kind: 'cursor', file: path.join(home, '.cursor', 'mcp.json'), profile: 'cursor', label: 'Cursor (user)' },
    { kind: 'cursor-project', file: path.join(cwd, '.cursor', 'mcp.json'), profile: projectProfile('cursor', cwd), label: 'Cursor (project)' },
  ];
}

function projectProfile(prefix: string, dir: string): string {
  const base = path.basename(path.resolve(dir)).toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^[^a-z0-9]+/, '').slice(0, 32) || 'project';
  const hash = crypto.createHash('sha256').update(path.resolve(dir).toLowerCase()).digest('hex').slice(0, 6);
  return `${prefix}-${base}-${hash}`;
}

export type ClientEntry = Record<string, unknown>;

export interface GatewayEntry {
  command: string;
  args: string[];
}

export interface ConversionResult {
  /** Servers for the MCPhantom profile, keyed by server id. */
  servers: Record<string, Record<string, unknown>>;
  /** Original client entries that were moved, keyed by their original name. */
  moved: Record<string, ClientEntry>;
  /** Original name → server id. */
  idMap: Record<string, string>;
  /** Entries left in the client config, with the reason. */
  skipped: { name: string; reason: string }[];
}

/** True if this client entry already launches MCPhantom. */
export function isGatewayEntry(entry: unknown): boolean {
  if (!entry || typeof entry !== 'object') return false;
  const e = entry as { command?: unknown; args?: unknown };
  const parts = [e.command, ...(Array.isArray(e.args) ? (e.args as unknown[]) : [])].filter((x): x is string => typeof x === 'string');
  const joined = parts.join(' ').toLowerCase();
  return /mcphantom/.test(joined) && parts.includes('run');
}

/**
 * Splits a client's `mcpServers` into what MCPhantom will proxy and what stays put. Pure: no I/O.
 */
export function convertEntries(mcpServers: Record<string, unknown>): ConversionResult {
  const result: ConversionResult = { servers: {}, moved: {}, idMap: {}, skipped: [] };
  const used = new Set<string>();
  for (const [name, raw] of Object.entries(mcpServers)) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      result.skipped.push({ name, reason: 'not an object' });
      continue;
    }
    const entry = raw as ClientEntry;
    if (isGatewayEntry(entry)) {
      result.skipped.push({ name, reason: 'already the MCPhantom gateway' });
      continue;
    }
    if (entry.disabled === true) {
      result.skipped.push({ name, reason: 'disabled in the client' });
      continue;
    }
    const type = typeof entry.type === 'string' ? entry.type : undefined;
    let server: Record<string, unknown>;
    if (typeof entry.command === 'string' && (type === undefined || type === 'stdio')) {
      server = { command: entry.command };
      if (Array.isArray(entry.args)) server.args = entry.args.map(String);
      if (isStringRecord(entry.env)) server.env = entry.env;
      if (typeof entry.cwd === 'string') server.cwd = entry.cwd;
    } else if (typeof entry.url === 'string' && (type === undefined || type === 'http' || type === 'streamable-http' || type === 'streamableHttp')) {
      server = { type: 'http', url: entry.url };
      if (isStringRecord(entry.headers)) server.headers = entry.headers;
    } else if (type === 'sse') {
      result.skipped.push({ name, reason: 'SSE transport is not supported by MCPhantom yet; this server is NOT protected' });
      continue;
    } else {
      result.skipped.push({ name, reason: `unrecognised entry (type ${type ?? 'unspecified'}); this server is NOT protected` });
      continue;
    }
    const id = uniqueId(name, used);
    used.add(id);
    result.servers[id] = server;
    result.moved[name] = entry;
    result.idMap[name] = id;
  }
  return result;
}

function isStringRecord(v: unknown): v is Record<string, string> {
  return !!v && typeof v === 'object' && !Array.isArray(v) && Object.values(v).every((x) => typeof x === 'string');
}

/** Derives a valid, unique server id from a client entry name. */
export function uniqueId(name: string, used: Set<string>): string {
  let base = name.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/-+/g, '-').replace(/^[^a-z]+/, '').replace(/-+$/, '').slice(0, 28);
  if (!base) base = 'server';
  let id = base;
  for (let n = 2; used.has(id) || !SERVER_ID_RE.test(id); n++) id = `${base}-${n}`.slice(0, 32);
  return id;
}

export function gatewayEntryName(existing: Record<string, unknown>): string {
  if (!('mcphantom' in existing)) return 'mcphantom';
  for (let n = 2; ; n++) if (!(`mcphantom-${n}` in existing)) return `mcphantom-${n}`;
}
