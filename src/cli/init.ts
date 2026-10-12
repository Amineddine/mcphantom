import crypto from 'node:crypto';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { stringify } from 'yaml';
import {
  convertEntries,
  gatewayEntryName,
  isGatewayEntry,
  knownClientTargets,
  type ClientEntry,
  type ClientKind,
  type ClientTarget,
  type GatewayEntry,
} from '../clients/clients.js';
import { formatZodError } from '../config/load.js';
import { PROFILE_NAME_RE, profilePath, type Paths } from '../config/paths.js';
import { ConfigSchema } from '../config/schema.js';
import { checkPrivate, ensurePrivateDir, restrictFile, writePrivateFile } from '../security/fileperms.js';
import { lineDiff } from '../util/diff.js';
import { UserError } from '../util/errors.js';

export interface Io {
  out(text: string): void;
  confirm(question: string): Promise<boolean>;
}

export interface InitOptions {
  client?: ClientKind | undefined;
  file?: string | undefined;
  profile?: string | undefined;
  yes: boolean;
  dryRun: boolean;
  cwd: string;
  paths: Paths;
  /** How the client should launch MCPhantom. Defaults to this Node binary + this CLI script. */
  gatewayCommand?: GatewayEntry | undefined;
}

/** Recorded next to the profile so `uninstall` can put the client config back. */
export interface OriginRecord {
  version: 1;
  client: ClientKind;
  file: string;
  entryName: string;
  createdAt: string;
  moved: Record<string, ClientEntry>;
  idMap: Record<string, string>;
}

export function originPath(paths: Paths, profile: string): string {
  return path.join(paths.profilesDir, `${profile}.origin.json`);
}

export async function runInit(opts: InitOptions, io: Io): Promise<void> {
  const target = pickTarget(opts, io);
  const profile = opts.profile ?? target.profile;
  if (!PROFILE_NAME_RE.test(profile)) throw new UserError(`Invalid profile name: ${profile}`, 'Use lowercase letters, digits, ".", "_" and "-".');

  const { text: before, json } = readClientConfig(target.file);
  const mcpServers = getMcpServers(json, target.file);
  const conv = convertEntries(mcpServers);

  for (const s of conv.skipped) io.out(`  • ${s.name}: left unchanged — ${s.reason}`);
  const movedNames = Object.keys(conv.moved);
  if (movedNames.length === 0) {
    io.out(`Nothing to do: no servers in ${target.file} can be moved behind MCPhantom.`);
    return;
  }

  const pPath = profilePath(opts.paths, profile);
  const oPath = originPath(opts.paths, profile);
  if (fs.existsSync(oPath)) {
    throw new UserError(
      `Profile '${profile}' is already installed into a client config (${oPath}).`,
      `Run \`mcphantom uninstall --profile ${profile}\` first, or pass --profile <other-name>.`,
    );
  }

  // Build the new client config: moved entries removed, one gateway entry added.
  const remaining: Record<string, unknown> = {};
  for (const [name, entry] of Object.entries(mcpServers)) if (!(name in conv.moved)) remaining[name] = entry;
  const entryName = gatewayEntryName(remaining);
  const gw = opts.gatewayCommand ?? defaultGatewayCommand();
  remaining[entryName] = { command: gw.command, args: [...gw.args, 'run', '--profile', profile] };
  const after = formatLike(before, { ...json, mcpServers: remaining });

  const profileDoc = { version: 1, servers: conv.servers };
  const check = ConfigSchema.safeParse(profileDoc);
  if (!check.success) throw new Error(`internal error: generated profile is invalid:\n${formatZodError(check.error)}`);
  const profileText =
    `# MCPhantom profile '${profile}', created by \`mcphantom init\` from ${target.file}\n` +
    `# Servers listed here are reached only through the MCPhantom gateway.\n` +
    `# This file may contain credentials copied from the client config; it is readable only by you.\n` +
    stringify(profileDoc);

  io.out(`\n${target.label}: ${target.file}`);
  io.out(`Moving ${movedNames.length} server(s) behind MCPhantom: ${movedNames.map((n) => `${n} → ${conv.idMap[n] ?? n}`).join(', ')}`);
  io.out(`Tools will appear to the client as <server>__<tool> (e.g. ${conv.idMap[movedNames[0] as string] ?? ''}__read_file).\n`);
  io.out(lineDiff(before, after));
  io.out(`\nProfile: ${pPath}`);

  if (opts.dryRun) {
    io.out('\n(dry run: nothing written)');
    return;
  }
  if (!opts.yes && !(await io.confirm('Apply these changes?'))) {
    io.out('Aborted; nothing written.');
    return;
  }

  ensurePrivateDir(opts.paths.configDir);
  ensurePrivateDir(opts.paths.profilesDir);
  const backupDir = path.join(opts.paths.configDir, 'backups');
  ensurePrivateDir(backupDir);
  const backup = path.join(backupDir, `${profile}-${new Date().toISOString().replace(/[:.]/g, '-')}-${path.basename(target.file)}`);
  // Client configs often hold credentials; backups are owner-only.
  writePrivateFile(backup, before);

  const origin: OriginRecord = {
    version: 1, client: target.kind, file: target.file, entryName, createdAt: new Date().toISOString(),
    moved: conv.moved, idMap: conv.idMap,
  };
  writePrivateFile(pPath, profileText);
  writePrivateFile(oPath, JSON.stringify(origin, null, 2) + '\n');
  writeClientConfig(target.file, before, after);

  io.out(`\nDone. Backup of the original client config: ${backup}`);
  io.out(`Restart ${target.label.replace(/ \(.*\)$/, '')} to pick up the change. Undo with: mcphantom uninstall --profile ${profile}`);
  io.out(`Tip: run \`mcphantom suggest --profile ${profile}\` to get per-tool classification suggestions from the servers' annotations.`);
}

export interface UninstallOptions {
  profile: string;
  yes: boolean;
  dryRun: boolean;
  paths: Paths;
}

export async function runUninstall(opts: UninstallOptions, io: Io): Promise<void> {
  const oPath = originPath(opts.paths, opts.profile);
  let origin: OriginRecord;
  try {
    origin = JSON.parse(fs.readFileSync(oPath, 'utf8')) as OriginRecord;
  } catch {
    throw new UserError(`No install record for profile '${opts.profile}' (${oPath}).`, 'List profiles with `mcphantom doctor`.');
  }
  const { text: before, json } = readClientConfig(origin.file);
  const mcpServers = getMcpServers(json, origin.file);
  const next: Record<string, unknown> = {};
  const gw = mcpServers[origin.entryName];
  const gwArgs = (gw as { args?: unknown } | undefined)?.args;
  const ours = isGatewayEntry(gw) && Array.isArray(gwArgs) && gwArgs.some((a, i) => a === '--profile' && gwArgs[i + 1] === opts.profile);
  if (!ours) io.out(`  • gateway entry '${origin.entryName}' not found (already removed?)`);
  for (const [name, entry] of Object.entries(mcpServers)) {
    if (name === origin.entryName && ours) continue;
    next[name] = entry;
  }
  for (const [name, entry] of Object.entries(origin.moved)) {
    if (name in next) {
      io.out(`  • '${name}' already exists in the client config; keeping the current entry`);
      continue;
    }
    next[name] = entry;
  }
  const after = formatLike(before, { ...json, mcpServers: next });
  io.out(`${origin.file}\n`);
  io.out(lineDiff(before, after));
  io.out(`\nNote: servers you added to the profile by hand after init are not copied back; see ${profilePath(opts.paths, opts.profile)}.`);
  if (opts.dryRun) {
    io.out('\n(dry run: nothing written)');
    return;
  }
  if (!opts.yes && !(await io.confirm('Restore the client config?'))) {
    io.out('Aborted; nothing written.');
    return;
  }
  writeClientConfig(origin.file, before, after);
  fs.rmSync(oPath, { force: true });
  io.out(`\nRestored. The profile file was kept: ${profilePath(opts.paths, opts.profile)}`);
}

function pickTarget(opts: InitOptions, io: Io): ClientTarget {
  if (opts.file) {
    const file = path.resolve(opts.cwd, opts.file);
    const kind = opts.client ?? 'file';
    return { kind, file, profile: opts.profile ?? `file-${crypto.createHash('sha256').update(file.toLowerCase()).digest('hex').slice(0, 8)}`, label: file };
  }
  const targets = knownClientTargets(opts.cwd);
  if (opts.client) {
    const t = targets.find((x) => x.kind === opts.client);
    if (!t) throw new UserError(`Unknown client: ${opts.client}`, `Choose one of: ${targets.map((x) => x.kind).join(', ')}, or pass --file.`);
    return t;
  }
  const found = targets.filter((t) => fs.existsSync(t.file));
  if (found.length === 1 && found[0]) return found[0];
  if (found.length === 0) {
    throw new UserError(
      'No MCP client config found.',
      `Looked for:\n${targets.map((t) => `  ${t.kind.padEnd(15)} ${t.file}`).join('\n')}\nPass --client <name> or --file <path>.`,
    );
  }
  io.out('Several MCP client configs were found:');
  for (const t of found) io.out(`  ${t.kind.padEnd(15)} ${t.file}`);
  throw new UserError('Choose one with --client <name>.');
}

function readClientConfig(file: string): { text: string; json: Record<string, unknown> } {
  let text: string;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') throw new UserError(`Client config not found: ${file}`);
    throw err;
  }
  let json: unknown;
  try {
    json = JSON.parse(text.replace(/^\uFEFF/, ''));
  } catch (err) {
    throw new UserError(`${file} is not valid JSON: ${(err as Error).message}`, 'Fix the file (or restore it from a backup) and re-run.');
  }
  if (!json || typeof json !== 'object' || Array.isArray(json)) throw new UserError(`${file} does not contain a JSON object.`);
  return { text, json: json as Record<string, unknown> };
}

function getMcpServers(json: Record<string, unknown>, file: string): Record<string, unknown> {
  const s = json.mcpServers;
  if (s === undefined) return {};
  if (!s || typeof s !== 'object' || Array.isArray(s)) throw new UserError(`"mcpServers" in ${file} is not an object.`);
  return s as Record<string, unknown>;
}

/**
 * Atomic replace that refuses to clobber concurrent edits: the file must still contain exactly what
 * was shown in the diff.
 */
function writeClientConfig(file: string, expectedBefore: string, after: string): void {
  const current = fs.readFileSync(file, 'utf8');
  if (current !== expectedBefore) {
    throw new UserError(`${file} changed while MCPhantom was editing it; nothing was written.`, 'Close the client and re-run the command.');
  }
  const mode = fs.statSync(file).mode & 0o777;
  // On Windows the replacement inherits the folder's ACL, which could be looser than the original's.
  const wasPrivate = checkPrivate(file).ok;
  const tmp = `${file}.mcphantom-${crypto.randomBytes(4).toString('hex')}.tmp`;
  fs.writeFileSync(tmp, after, { mode, flag: 'wx' });
  try {
    fs.renameSync(tmp, file);
  } catch (err) {
    fs.rmSync(tmp, { force: true });
    throw err;
  }
  if (wasPrivate) restrictFile(file);
}

/** Re-serialises with the original file's indentation and trailing newline to keep diffs minimal. */
export function formatLike(original: string, value: unknown): string {
  const m = /^[ \t]*\{[^\n]*\n([ \t]+)\S/m.exec(original);
  const indent = m?.[1] ?? '  ';
  const text = JSON.stringify(value, null, indent.includes('\t') ? '\t' : indent.length);
  return original.endsWith('\n') || original.length === 0 ? text + '\n' : text;
}

/**
 * Absolute paths, not `mcphantom` on PATH: GUI clients (Claude Desktop) often start with a minimal
 * PATH, and on Windows they cannot spawn `.cmd` shims without a shell.
 */
export function defaultGatewayCommand(): GatewayEntry {
  const here = fileURLToPath(import.meta.url);
  const ext = path.extname(here);
  const main = path.join(path.dirname(here), `main${ext}`);
  if (ext === '.ts') {
    // Running from source (development): load TypeScript through tsx.
    const require = createRequire(import.meta.url);
    const tsx = pathToFileURL(require.resolve('tsx')).href;
    return { command: process.execPath, args: ['--import', tsx, main] };
  }
  return { command: process.execPath, args: [main] };
}
