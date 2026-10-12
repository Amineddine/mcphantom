import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';
import { afterEach, describe, expect, it } from 'vitest';
import { acesToRemove, checkPrivate, parseSddl } from '../src/security/fileperms.js';
import { SqliteStore, type StoreOptions } from '../src/store/store.js';
import { silentLogger } from '../src/util/log.js';
import { tempDir } from './helpers.js';

const dirs: string[] = [];
const stores: SqliteStore[] = [];

function open(overrides: Partial<StoreOptions> = {}): SqliteStore {
  const dataDir = overrides.dataDir ?? path.join(tempDir(), 'data');
  dirs.push(path.dirname(dataDir));
  const s = new SqliteStore({
    dataDir, payloads: 'redacted', maxPayloadBytes: 65_536, retentionDays: 14, retentionMaxMb: 256,
    knownSecrets: [], insecurePermissions: 'fix', logger: silentLogger, ...overrides,
  });
  stores.push(s);
  return s;
}

afterEach(() => {
  for (const s of stores.splice(0)) s.close();
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});

describe('SqliteStore', () => {
  it('stores events with redacted payloads and errors', () => {
    const s = open({ knownSecrets: ['configured-secret-value'] });
    s.startSession({ id: 's1' });
    s.append({ sessionId: 's1', kind: 'request', method: 'tools/call', payload: { args: { key: 'AKIAIOSFODNN7EXAMPLE', other: 'configured-secret-value' } }, error: ['failed with tok', 'en=', 'abcdef123456'].join('') });
    const [e] = s.events();
    expect(e?.payload).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(e?.payload).not.toContain('configured-secret-value');
    expect(e?.error).not.toContain('abcdef123456');
    expect(JSON.parse(e?.payload ?? 'null')).toMatchObject({ args: { key: '[REDACTED:aws-access-key-id]' } });
  });

  it('keeps nothing on disk for redacted values (DB and WAL)', () => {
    const s = open();
    s.append({ sessionId: 's', kind: 'request', payload: { k: 'AKIAIOSFODNN7EXAMPLE' } });
    const bytes = Buffer.concat(['', '-wal'].filter((x) => fs.existsSync(s.file + x)).map((x) => fs.readFileSync(s.file + x)));
    expect(bytes.includes(Buffer.from('AKIAIOSFODNN7EXAMPLE'))).toBe(false);
  });

  it('payloads: none stores no bodies', () => {
    const s = open({ payloads: 'none' });
    s.append({ sessionId: 's', kind: 'request', payload: { a: 1 } });
    expect(s.events()[0]?.payload).toBeNull();
  });

  it('truncated payloads are still valid JSON', () => {
    const s = open({ maxPayloadBytes: 300 });
    s.append({ sessionId: 's', kind: 'request', payload: { big: 'word '.repeat(500) } });
    const p = s.events()[0]?.payload ?? '';
    expect(p.length).toBeLessThan(400);
    expect(() => JSON.parse(p) as unknown).not.toThrow();
  });

  it('prunes by age', () => {
    const s = open({ retentionDays: 1 });
    s.append({ sessionId: 's', kind: 'request' });
    expect(s.prune(Date.now() + 2 * 86_400_000).deleted).toBe(1);
    expect(s.events()).toHaveLength(0);
  });

  it('prunes oldest-first by size', () => {
    const s = open({ retentionMaxMb: 0.25, payloads: 'full', maxPayloadBytes: 1_048_576 });
    // Incompressible-ish payloads so the DB really grows past the budget.
    for (let i = 0; i < 400; i++) s.append({ sessionId: 's', kind: 'request', name: `e${i}`, payload: { blob: `${i}-`.repeat(1000) } });
    const { deleted } = s.prune();
    expect(deleted).toBeGreaterThan(0);
    const remaining = s.events({ limit: 10_000 });
    expect(remaining.length).toBeLessThan(400);
    expect(remaining[remaining.length - 1]?.name).toBe('e399'); // newest kept
  });

  it('refuses a database from a newer schema version', () => {
    const s = open();
    const file = s.file;
    const dataDir = path.dirname(file);
    s.close();
    const db = new Database(file);
    db.pragma('user_version = 99');
    db.close();
    expect(() => open({ dataDir })).toThrow(/newer than this MCPhantom/);
  });
});

describe('file permissions', () => {
  it('creates the data dir and DB owner-only', () => {
    const s = open();
    expect(checkPrivate(path.dirname(s.file))).toEqual({ ok: true, problems: [] });
    expect(checkPrivate(s.file)).toEqual({ ok: true, problems: [] });
  });

  it('fixes an existing world-accessible data dir by default', () => {
    const parent = tempDir();
    dirs.push(parent);
    const dataDir = path.join(parent, 'data');
    fs.mkdirSync(dataDir);
    if (process.platform !== 'win32') fs.chmodSync(dataDir, 0o777);
    // On Windows a fresh temp subdirectory inherits SYSTEM/Administrators ACEs: not private.
    expect(checkPrivate(dataDir).ok).toBe(false);
    open({ dataDir });
    expect(checkPrivate(dataDir).ok).toBe(true);
  });

  it('refuses an insecure data dir when configured to', () => {
    const parent = tempDir();
    dirs.push(parent);
    const dataDir = path.join(parent, 'data');
    fs.mkdirSync(dataDir);
    if (process.platform !== 'win32') fs.chmodSync(dataDir, 0o755);
    expect(() => open({ dataDir, insecurePermissions: 'refuse' })).toThrow(/Refusing to use/);
  });

  it('parses SDDL DACLs, including well-known aliases', () => {
    const acl = parseSddl('D:PAI(A;OICI;FA;;;S-1-5-21-1-2-3-1001)(A;;FA;;;SY)(D;;FA;;;WD)');
    expect(acl.protectedDacl).toBe(true);
    expect(acl.aces).toEqual([
      { type: 'A', sid: 'S-1-5-21-1-2-3-1001', resolved: true },
      { type: 'A', sid: 'S-1-5-18', resolved: true },
      { type: 'D', sid: 'S-1-1-0', resolved: true },
    ]);
    expect(parseSddl('D:AI(A;ID;FA;;;BA)').protectedDacl).toBe(false);
  });

  // Regression (found by the first Windows CI run): GitHub's runners run as the built-in
  // Administrator, RID 500, which SDDL writes as `LA`. Treating `LA` as "someone else" removed the
  // user's only ACE and locked MCPhantom out of its own directory.
  it('resolves RID-relative aliases against the user SID (built-in Administrator = LA)', () => {
    const admin = 'S-1-5-21-111-222-333-500';
    const acl = parseSddl('D:PAI(A;OICI;FA;;;LA)', admin);
    expect(acl.aces).toEqual([{ type: 'A', sid: admin, resolved: true }]);
    expect(acesToRemove(acl, admin)).toEqual([]);
  });

  it('never removes an ACE it cannot resolve (it might be the user)', () => {
    const user = 'S-1-5-21-111-222-333-1001';
    const acl = parseSddl('D:PAI(A;;FA;;;S-1-5-21-111-222-333-1001)(A;;FA;;;LA)(A;;FA;;;ZZ)(A;;FA;;;SY)');
    // Without a user SID, LA cannot be resolved; neither it nor the unknown ZZ may be removed.
    expect(acesToRemove(acl, user)).toEqual(['S-1-5-18']);
    expect(acesToRemove(parseSddl('D:PAI(A;;FA;;;LA)', user), user)).toEqual(['S-1-5-21-111-222-333-500']);
  });
});
