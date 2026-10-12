import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/**
 * Owner-only file permissions for MCPhantom's own state (event DB, config, profiles, lockfile,
 * policy). POSIX: dirs 0700, files 0600. Windows: a protected DACL (no inherited ACEs) with a single
 * allow-full-control ACE for the current user's SID — the 0600 equivalent.
 *
 * This keeps *other* local users out. It does not stop processes running as the same user,
 * including upstream MCP servers; see DESIGN.md §1 "Same-user tampering".
 */

export interface PermCheck {
  ok: boolean;
  problems: string[];
}

const isWin = process.platform === 'win32';

export function ensurePrivateDir(dir: string): void {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (isWin) winRestrict(dir, true);
  else fs.chmodSync(dir, 0o700);
}

/** Creates the file if missing (empty) and restricts it. */
export function ensurePrivateFile(file: string): void {
  const fd = fs.openSync(file, 'a', 0o600);
  fs.closeSync(fd);
  restrictFile(file);
}

export function restrictFile(file: string): void {
  if (isWin) winRestrict(file, false);
  else fs.chmodSync(file, 0o600);
}

/** Writes a file so that it is never readable by others, not even briefly. Atomic (temp + rename). */
export function writePrivateFile(file: string, content: string): void {
  const dir = path.dirname(file);
  const tmp = path.join(dir, `.${path.basename(file)}.${crypto.randomBytes(6).toString('hex')}.tmp`);
  const fd = fs.openSync(tmp, 'wx', 0o600);
  try {
    if (isWin) winRestrict(tmp, false);
    fs.writeFileSync(fd, content);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  renameWithRetry(tmp, file);
  restrictFile(file);
}

export function checkPrivate(p: string): PermCheck {
  if (!fs.existsSync(p)) return { ok: true, problems: [] };
  return isWin ? winCheck(p) : posixCheck(p);
}

function posixCheck(p: string): PermCheck {
  const st = fs.statSync(p);
  const problems: string[] = [];
  const mode = st.mode & 0o777;
  if ((mode & 0o077) !== 0) problems.push(`${p} has mode ${mode.toString(8).padStart(3, '0')}; expected ${st.isDirectory() ? '700' : '600'}`);
  const uid = process.getuid?.();
  if (uid !== undefined && st.uid !== uid) problems.push(`${p} is owned by uid ${st.uid}, not the current user (${uid})`);
  return { ok: problems.length === 0, problems };
}

// ---------------------------------------------------------------------------------------------
// Windows

let cachedSid: string | undefined;

/**
 * System binaries are invoked by absolute path. Resolving them through PATH picks up look-alikes
 * (Git for Windows ships a GNU `whoami`) and is a hijack vector.
 */
function system32(exe: string): string {
  const root = process.env.SystemRoot ?? process.env.windir ?? 'C:\\Windows';
  return path.win32.join(root, 'System32', exe);
}

export function currentUserSid(): string {
  if (cachedSid) return cachedSid;
  // CSV output: "DOMAIN\user","S-1-5-21-..."
  const out = execFileSync(system32('whoami.exe'), ['/user', '/fo', 'csv', '/nh'], { encoding: 'utf8', windowsHide: true });
  const m = /"(S-1-[0-9-]+)"/.exec(out);
  if (!m?.[1]) throw new Error(`could not determine current user SID from whoami output: ${out.trim()}`);
  cachedSid = m[1];
  return cachedSid;
}

function icacls(args: string[]): string {
  return execFileSync(system32('icacls.exe'), args, { encoding: 'utf8', windowsHide: true });
}

function winRestrict(p: string, isDir: boolean): void {
  const sid = currentUserSid();
  const grant = isDir ? `*${sid}:(OI)(CI)F` : `*${sid}:F`;
  icacls([p, '/inheritance:r', '/grant:r', grant, '/q']);
  // Remove any remaining explicit ACEs for other principals (e.g. pre-existing grants).
  const acl = readSddl(p);
  for (const ace of acl.aces) {
    if (ace.sid !== sid) icacls([p, '/remove:g', `*${ace.sidForIcacls}`, '/remove:d', `*${ace.sidForIcacls}`, '/q']);
  }
}

interface Ace {
  type: string;
  sid: string;
  /** Full SID, or the SDDL alias resolved to a well-known SID string. */
  sidForIcacls: string;
}

interface Sddl {
  protectedDacl: boolean;
  aces: Ace[];
}

/** SDDL aliases icacls/Windows may emit for well-known principals. */
const SDDL_ALIASES: Record<string, string> = {
  SY: 'S-1-5-18', BA: 'S-1-5-32-544', BU: 'S-1-5-32-545', WD: 'S-1-1-0', AU: 'S-1-5-11',
  CO: 'S-1-3-0', CG: 'S-1-3-1', OW: 'S-1-3-4', IU: 'S-1-5-4', NS: 'S-1-5-20', LS: 'S-1-5-19',
  AN: 'S-1-5-7', PU: 'S-1-5-32-547', BG: 'S-1-5-32-546', AC: 'S-1-15-2-1', RC: 'S-1-5-12',
};

/**
 * Reads a DACL as SDDL through `icacls /save`, which is locale-independent (SIDs rather than
 * localized account names like "AUTORITE NT\Système").
 */
export function readSddl(p: string): Sddl {
  const tmp = path.join(os.tmpdir(), `mcphantom-acl-${crypto.randomBytes(8).toString('hex')}.txt`);
  try {
    icacls([p, '/save', tmp, '/q']);
    const raw = fs.readFileSync(tmp);
    // icacls writes UTF-16LE; tolerate a BOM.
    const text = raw.toString('utf16le').replace(/^\uFEFF/, '');
    const line = text.split(/\r?\n/).find((l) => l.startsWith('D:'));
    if (!line) throw new Error(`no DACL in icacls output for ${p}`);
    return parseSddl(line.trim());
  } finally {
    fs.rmSync(tmp, { force: true });
  }
}

export function parseSddl(dacl: string): Sddl {
  const flagsEnd = dacl.indexOf('(');
  const flags = flagsEnd < 0 ? dacl.slice(2) : dacl.slice(2, flagsEnd);
  const aces: Ace[] = [];
  for (const m of dacl.matchAll(/\(([^)]*)\)/g)) {
    const parts = (m[1] ?? '').split(';');
    const type = parts[0] ?? '';
    const rawSid = parts[5] ?? '';
    const sid = SDDL_ALIASES[rawSid] ?? rawSid;
    aces.push({ type, sid, sidForIcacls: sid });
  }
  return { protectedDacl: flags.includes('P'), aces };
}

function winCheck(p: string): PermCheck {
  const sid = currentUserSid();
  const acl = readSddl(p);
  const problems: string[] = [];
  // Inherited ACEs are fine as long as they, too, name only the current user (files inside a private
  // directory inherit its single ACE). What matters is that no other principal is granted access.
  for (const ace of acl.aces) {
    if (ace.sid !== sid && !ace.type.startsWith('D')) problems.push(`${p} grants access to ${ace.sid}`);
  }
  if (!acl.aces.some((a) => a.sid === sid && a.type === 'A')) problems.push(`${p} has no access entry for the current user`);
  return { ok: problems.length === 0, problems };
}

function renameWithRetry(from: string, to: string): void {
  // On Windows a rename onto a file another process has open can fail transiently (EPERM/EBUSY).
  for (let attempt = 0; ; attempt++) {
    try {
      fs.renameSync(from, to);
      return;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (attempt >= 10 || (code !== 'EPERM' && code !== 'EBUSY' && code !== 'EACCES')) {
        fs.rmSync(from, { force: true });
        throw err;
      }
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20 * (attempt + 1));
    }
  }
}
