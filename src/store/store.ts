import path from 'node:path';
import Database from 'better-sqlite3';
import { Redactor, safeCut, TRUNCATED } from '../secrets/redact.js';
import { checkPrivate, ensurePrivateDir, ensurePrivateFile, restrictFile } from '../security/fileperms.js';
import type { Logger } from '../util/log.js';

export type EventKind =
  | 'session_start'
  | 'session_end'
  | 'upstream_connected'
  | 'upstream_failed'
  | 'upstream_closed'
  | 'request'
  | 'notification'
  | 'denied'
  | 'warning';

export interface EventInput {
  sessionId: string;
  kind: EventKind;
  server?: string | undefined;
  method?: string | undefined;
  /** Exposed (namespaced) tool or prompt name, when applicable. */
  name?: string | undefined;
  /** ok | error | denied */
  outcome?: string | undefined;
  durationMs?: number | undefined;
  payload?: unknown;
  error?: string | undefined;
}

export interface StoredEvent {
  id: number;
  ts: number;
  session_id: string;
  kind: string;
  server: string | null;
  method: string | null;
  name: string | null;
  outcome: string | null;
  duration_ms: number | null;
  payload: string | null;
  error: string | null;
}

export interface SessionInfo {
  id: string;
  clientName?: string | undefined;
  clientVersion?: string | undefined;
  profile?: string | undefined;
}

export interface Store {
  startSession(info: SessionInfo): void;
  updateSessionClient(id: string, clientName: string | undefined, clientVersion: string | undefined): void;
  endSession(id: string): void;
  append(event: EventInput): void;
  events(filter?: { sessionId?: string; kind?: EventKind; limit?: number }): StoredEvent[];
  prune(now?: number): { deleted: number };
  close(): void;
}

export interface StoreOptions {
  dataDir: string;
  payloads: 'redacted' | 'none' | 'full';
  maxPayloadBytes: number;
  retentionDays: number;
  retentionMaxMb: number;
  knownSecrets: readonly string[];
  insecurePermissions: 'fix' | 'warn' | 'refuse';
  logger: Logger;
}

const SCHEMA_VERSION = 1;

/**
 * SQLite event log. Payloads are redacted *before* they reach the database, so neither the DB nor its
 * WAL ever contains the raw value; `secure_delete` zeroes pruned rows on disk.
 */
export class SqliteStore implements Store {
  private readonly db: Database.Database;
  private readonly redactor: Redactor;
  private readonly opts: StoreOptions;
  private readonly insertStmt: Database.Statement;
  private pruneTimer: NodeJS.Timeout | undefined;
  readonly file: string;

  constructor(opts: StoreOptions) {
    this.opts = opts;
    this.redactor = new Redactor({ knownSecrets: opts.knownSecrets, budgetChars: Math.max(opts.maxPayloadBytes * 2, 65_536) });
    ensureSecureLocation(opts.dataDir, opts.insecurePermissions, opts.logger);
    this.file = path.join(opts.dataDir, 'events.db');
    ensureSecureFile(this.file, opts.insecurePermissions, opts.logger);
    this.db = new Database(this.file);
    try {
      this.db.pragma('busy_timeout = 5000');
      this.db.pragma('auto_vacuum = INCREMENTAL');
      this.db.pragma('journal_mode = WAL');
      this.db.pragma('synchronous = NORMAL');
      this.db.pragma('secure_delete = ON');
      this.migrate();
    } catch (err) {
      // Don't leak the handle: on Windows an open handle locks the file for every other process.
      this.db.close();
      throw err;
    }
    for (const side of ['-wal', '-shm']) {
      try {
        restrictFile(this.file + side);
      } catch {
        // Not created yet; it inherits the directory's owner-only permissions when it is.
      }
    }
    this.insertStmt = this.db.prepare(
      `INSERT INTO events (ts, session_id, kind, server, method, name, outcome, duration_ms, payload, error)
       VALUES (@ts, @session_id, @kind, @server, @method, @name, @outcome, @duration_ms, @payload, @error)`,
    );
    this.prune();
    this.pruneTimer = setInterval(() => {
      try {
        this.prune();
      } catch (err) {
        opts.logger.warn(`event log pruning failed: ${String(err)}`);
      }
    }, 3_600_000);
    this.pruneTimer.unref();
  }

  private migrate(): void {
    const version = this.db.pragma('user_version', { simple: true }) as number;
    if (version > SCHEMA_VERSION) {
      throw new Error(`event database ${this.file} has schema v${version}, newer than this MCPhantom (v${SCHEMA_VERSION})`);
    }
    if (version < 1) {
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS sessions (
          id TEXT PRIMARY KEY,
          started_at INTEGER NOT NULL,
          ended_at INTEGER,
          client_name TEXT,
          client_version TEXT,
          profile TEXT,
          pid INTEGER
        );
        CREATE TABLE IF NOT EXISTS events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts INTEGER NOT NULL,
          session_id TEXT NOT NULL,
          kind TEXT NOT NULL,
          server TEXT,
          method TEXT,
          name TEXT,
          outcome TEXT,
          duration_ms REAL,
          payload TEXT,
          error TEXT
        );
        CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
        CREATE INDEX IF NOT EXISTS events_session ON events(session_id, id);
        PRAGMA user_version = 1;
      `);
    }
  }

  startSession(info: SessionInfo): void {
    this.db
      .prepare('INSERT OR REPLACE INTO sessions (id, started_at, client_name, client_version, profile, pid) VALUES (?, ?, ?, ?, ?, ?)')
      .run(info.id, Date.now(), info.clientName ?? null, info.clientVersion ?? null, info.profile ?? null, process.pid);
  }

  updateSessionClient(id: string, clientName: string | undefined, clientVersion: string | undefined): void {
    this.db.prepare('UPDATE sessions SET client_name = ?, client_version = ? WHERE id = ?').run(clientName ?? null, clientVersion ?? null, id);
  }

  endSession(id: string): void {
    this.db.prepare('UPDATE sessions SET ended_at = ? WHERE id = ?').run(Date.now(), id);
  }

  append(e: EventInput): void {
    this.insertStmt.run({
      ts: Date.now(),
      session_id: e.sessionId,
      kind: e.kind,
      server: e.server ?? null,
      method: e.method ?? null,
      name: e.name ?? null,
      outcome: e.outcome ?? null,
      duration_ms: e.durationMs ?? null,
      payload: e.payload === undefined ? null : this.serializePayload(e.payload),
      error: e.error === undefined ? null : this.redactor.redactString(safeCut(e.error, 4096)),
    });
  }

  /** Exposed for tests: exactly what would be written for a payload. */
  serializePayload(payload: unknown): string | null {
    const mode = this.opts.payloads;
    if (mode === 'none') return null;
    const value = mode === 'redacted' ? this.redactor.redactValue(payload) : payload;
    let json: string;
    try {
      // Callers never pass undefined (append() skips it), and MCP payloads are plain JSON.
      json = JSON.stringify(value);
    } catch {
      return JSON.stringify('[UNSERIALIZABLE]');
    }
    if (json.length <= this.opts.maxPayloadBytes) return json;
    // The cut JSON is no longer parseable; store it as a JSON string so readers always get valid JSON.
    return JSON.stringify(json.slice(0, this.opts.maxPayloadBytes) + TRUNCATED);
  }

  events(filter: { sessionId?: string; kind?: EventKind; limit?: number } = {}): StoredEvent[] {
    const where: string[] = [];
    const args: (string | number)[] = [];
    if (filter.sessionId) {
      where.push('session_id = ?');
      args.push(filter.sessionId);
    }
    if (filter.kind) {
      where.push('kind = ?');
      args.push(filter.kind);
    }
    args.push(filter.limit ?? 1000);
    const sql = `SELECT * FROM events ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY id ASC LIMIT ?`;
    return this.db.prepare(sql).all(...args) as StoredEvent[];
  }

  prune(now: number = Date.now()): { deleted: number } {
    const cutoff = now - this.opts.retentionDays * 86_400_000;
    let deleted = this.db.prepare('DELETE FROM events WHERE ts < ?').run(cutoff).changes;
    this.db.prepare('DELETE FROM sessions WHERE started_at < ? AND id NOT IN (SELECT DISTINCT session_id FROM events)').run(cutoff);
    const maxBytes = this.opts.retentionMaxMb * 1024 * 1024;
    // Approximate data size; drop the oldest 10% repeatedly until under budget.
    for (let i = 0; i < 20 && this.dataBytes() > maxBytes; i++) {
      const count = (this.db.prepare('SELECT COUNT(*) AS n FROM events').get() as { n: number }).n;
      if (count === 0) break;
      const n = Math.max(1, Math.ceil(count / 10));
      deleted += this.db.prepare('DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id ASC LIMIT ?)').run(n).changes;
      this.db.pragma('incremental_vacuum');
    }
    if (deleted > 0) {
      this.db.pragma('incremental_vacuum');
      this.db.pragma('wal_checkpoint(TRUNCATE)');
    }
    return { deleted };
  }

  private dataBytes(): number {
    const pageSize = this.db.pragma('page_size', { simple: true }) as number;
    const pages = this.db.pragma('page_count', { simple: true }) as number;
    const free = this.db.pragma('freelist_count', { simple: true }) as number;
    return (pages - free) * pageSize;
  }

  close(): void {
    if (this.pruneTimer) clearInterval(this.pruneTimer);
    this.pruneTimer = undefined;
    if (this.db.open) this.db.close();
  }
}

/**
 * Creates the data directory owner-only and verifies it. `insecure` controls what happens when an
 * existing directory or DB is accessible to other users.
 */
export function ensureSecureLocation(dir: string, insecure: 'fix' | 'warn' | 'refuse', logger: Logger): void {
  const existed = checkPrivate(dir);
  if (!existed.ok) {
    if (insecure === 'refuse') {
      throw new Error(`Refusing to use ${dir}: ${existed.problems.join('; ')}`);
    }
    if (insecure === 'warn') {
      for (const p of existed.problems) logger.warn(`insecure permissions: ${p}`);
      return;
    }
    for (const p of existed.problems) logger.warn(`fixing insecure permissions: ${p}`);
  }
  ensurePrivateDir(dir);
  const after = checkPrivate(dir);
  if (!after.ok) throw new Error(`Could not restrict ${dir} to the current user: ${after.problems.join('; ')}`);
}

/** Like {@link ensureSecureLocation}, for a single file (created empty if missing). */
export function ensureSecureFile(file: string, insecure: 'fix' | 'warn' | 'refuse', logger: Logger): void {
  const existed = checkPrivate(file);
  if (!existed.ok) {
    if (insecure === 'refuse') throw new Error(`Refusing to use ${file}: ${existed.problems.join('; ')}`);
    for (const p of existed.problems) logger.warn(`${insecure === 'warn' ? '' : 'fixing '}insecure permissions: ${p}`);
    if (insecure === 'warn') return;
  }
  ensurePrivateFile(file);
  const after = checkPrivate(file);
  if (!after.ok) throw new Error(`Could not restrict ${file} to the current user: ${after.problems.join('; ')}`);
}
