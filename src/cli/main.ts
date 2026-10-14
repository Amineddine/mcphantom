#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline/promises';
import { parseArgs } from 'node:util';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import type { ClientKind } from '../clients/clients.js';
import { loadConfigFile } from '../config/load.js';
import { profilePath, PROFILE_NAME_RE, resolvePaths, type Paths } from '../config/paths.js';
import { Gateway } from '../gateway/gateway.js';
import { checkPrivate } from '../security/fileperms.js';
import { ensureSecureFile, SqliteStore } from '../store/store.js';
import { errorMessage, UserError } from '../util/errors.js';
import { createLogger } from '../util/log.js';
import { VERSION } from '../version.js';
import { runApprove, runLockDiff } from './approve.js';
import { runPolicyLint, runPolicyTest, runPolicyExplain } from './policy.js';
import { runSuggest } from './suggest-cmd.js';
import { BOTTOM, type Label } from '../taint/labels.js';
import { runInit, runUninstall, type Io } from './init.js';
import { loadLockfile } from '../rugpull/lockfile.js';
import { RugpullChecker } from '../rugpull/checker.js';
import { runTrace } from './trace.js';

const HELP = `MCPhantom ${VERSION} — security gateway for MCP

Usage:
  mcphantom init [--client <name> | --file <path>] [--profile <name>] [--yes] [--dry-run]
      Move the MCP servers of a client config behind MCPhantom (shows a diff, keeps a backup).
      Clients: claude-code (project .mcp.json), claude-desktop, cursor, cursor-project.
  mcphantom uninstall --profile <name> [--yes] [--dry-run]
      Put the client config back the way it was.
  mcphantom run (--profile <name> | --config <file>)
      Run the gateway on stdio. This is what the MCP client launches.
  mcphantom doctor [--profile <name> | --config <file>]
      Show paths, profiles and permission checks; validate a config.
  mcphantom trace [--last] [--json] [--session <id>] [--config <file>]
      Show the taint trace (context labels, decisions, evidence) for a session.
  mcphantom approve (--profile <name> | --config <file>) [--yes]
      Pin the servers' current tool/prompt/instruction definitions into the lockfile.
  mcphantom lock diff (--profile <name> | --config <file>)
      Show how the live definitions differ from the approved lockfile.
  mcphantom policy lint | test --fixtures <f.yaml> | explain --tool <t> [--arg k=v] [--context i/c]
      Lint rules against live schemas, run decision fixtures, or dry-run one tool call.
  mcphantom suggest (--profile <name> | --config <file>) [--write] [--accept-loose]
      Suggest per-tool classifications from server annotations/names (server-claimed; looser ones
      need --accept-loose).
  mcphantom --version | --help
`;

const out = (text: string): void => {
  process.stdout.write(text + '\n');
};

const io: Io = {
  out,
  async confirm(question) {
    if (!process.stdin.isTTY) {
      throw new UserError('Confirmation needed but stdin is not a terminal.', 'Re-run with --yes to apply without asking, or --dry-run to preview.');
    }
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    try {
      const answer = await rl.question(`${question} [y/N] `);
      return /^y(es)?$/i.test(answer.trim());
    } finally {
      rl.close();
    }
  },
};

async function main(argv: string[]): Promise<number> {
  const [cmd, ...rest] = argv;
  switch (cmd) {
    case undefined:
    case 'help':
    case '--help':
    case '-h':
      out(HELP);
      return cmd === undefined ? 1 : 0;
    case '--version':
    case '-v':
    case 'version':
      out(VERSION);
      return 0;
    case 'run':
      return cmdRun(rest);
    case 'init':
      return cmdInit(rest);
    case 'uninstall':
      return cmdUninstall(rest);
    case 'doctor':
      return cmdDoctor(rest);
    case 'trace':
      return cmdTrace(rest);
    case 'approve':
      return cmdApprove(rest);
    case 'lock':
      return cmdLock(rest);
    case 'policy':
      return cmdPolicy(rest);
    case 'suggest':
      return cmdSuggest(rest);
    default:
      throw new UserError(`Unknown command: ${cmd}`, 'Run `mcphantom --help` for usage.');
  }
}

function parse<T extends Record<string, { type: 'string' | 'boolean' }>>(args: string[], options: T) {
  try {
    return parseArgs({ args, options, strict: true, allowPositionals: false }).values;
  } catch (err) {
    throw new UserError(errorMessage(err), 'Run `mcphantom --help` for usage.');
  }
}

function resolveConfigFile(paths: Paths, v: { profile?: string | undefined; config?: string | undefined }): { file: string; profile?: string } {
  if (v.profile && v.config) throw new UserError('Pass either --profile or --config, not both.');
  if (v.config) return { file: path.resolve(v.config) };
  if (v.profile) {
    if (!PROFILE_NAME_RE.test(v.profile)) throw new UserError(`Invalid profile name: ${v.profile}`);
    return { file: profilePath(paths, v.profile), profile: v.profile };
  }
  throw new UserError('Pass --profile <name> or --config <file>.', 'Create a profile with `mcphantom init`.');
}

async function cmdRun(args: string[]): Promise<number> {
  const v = parse(args, { profile: { type: 'string' }, config: { type: 'string' } });
  const paths = resolvePaths();
  const { file, profile } = resolveConfigFile(paths, v);
  const loaded = loadConfigFile(file);
  const cfg = loaded.config;
  const logger = createLogger(cfg.logging.level);

  // The config can hold credentials for upstream servers: owner-only, like everything else we store.
  ensureSecureFile(file, cfg.security.insecure_permissions, logger);
  if (cfg.logging.payloads === 'full') logger.warn('logging.payloads is "full": tool arguments and results are stored unredacted.');

  const store = new SqliteStore({
    dataDir: cfg.data_dir ? path.resolve(path.dirname(file), cfg.data_dir) : paths.dataDir,
    payloads: cfg.logging.payloads,
    maxPayloadBytes: cfg.logging.max_payload_bytes,
    retentionDays: cfg.retention.days,
    retentionMaxMb: cfg.retention.max_mb,
    knownSecrets: loaded.secrets,
    redactEntropy: cfg.secrets.entropy.redact,
    insecurePermissions: cfg.security.insecure_permissions,
    logger,
  });
  const sessionId = crypto.randomUUID();
  store.startSession({ id: sessionId, profile });
  store.append({ sessionId, kind: 'session_start', payload: { version: VERSION, config: file, servers: Object.keys(cfg.servers) } });

  // Load and verify the rug-pull lockfile. A tampered/foreign signature refuses to start by default.
  const lock = loadLockfile(file, paths.configDir);
  // Anything other than a verified or absent lockfile fails closed by default: a corrupted/truncated
  // lockfile must not silently switch rug-pull enforcement off.
  if (lock.integrity === 'bad-signature' || lock.integrity === 'missing-key' || lock.integrity === 'malformed') {
    const detail =
      lock.integrity === 'bad-signature' ? 'failed HMAC verification (tampered, or a different key/machine)'
        : lock.integrity === 'missing-key' ? 'has no HMAC key to verify against'
          : 'is malformed (corrupted or truncated)';
    if (cfg.rugpull.on_bad_signature === 'refuse') {
      throw new UserError(`Lockfile ${lock.path} ${detail}.`, 'Re-approve with `mcphantom approve`, or set rugpull.on_bad_signature: warn to proceed unverified.');
    }
    logger.warn(`lockfile ${detail}; proceeding unverified (rugpull.on_bad_signature: warn)`);
  }
  const locked = lock.integrity === 'ok' || (lock.integrity !== 'empty' && cfg.rugpull.on_bad_signature === 'warn');
  const rugpull = new RugpullChecker(lock.data, locked);
  const gateway = await Gateway.create({ config: cfg, store, logger, sessionId, version: VERSION, rugpull });
  let finished = false;
  const finish = async (reason: string): Promise<void> => {
    if (finished) return;
    finished = true;
    await gateway.close();
    try {
      store.append({ sessionId, kind: 'session_end', payload: { reason } });
      store.endSession(sessionId);
    } finally {
      store.close();
    }
  };
  const done = new Promise<void>((resolve) => {
    void gateway.disconnected.then(() => finish('client disconnected')).then(resolve);
    for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP'] as const) {
      process.once(sig, () => {
        void finish(`signal ${sig}`).then(resolve);
      });
    }
  });
  await gateway.connect(new StdioServerTransport());
  logger.info(`gateway ready (session ${sessionId}, ${gateway.upstreams.size} server(s))`);
  await done;
  return 0;
}

async function cmdInit(args: string[]): Promise<number> {
  const v = parse(args, {
    client: { type: 'string' }, file: { type: 'string' }, profile: { type: 'string' },
    yes: { type: 'boolean' }, 'dry-run': { type: 'boolean' },
  });
  const clients = ['claude-code', 'claude-desktop', 'cursor', 'cursor-project'];
  if (v.client !== undefined && !clients.includes(v.client)) {
    throw new UserError(`Unknown client: ${v.client}`, `Choose one of: ${clients.join(', ')}, or pass --file <path>.`);
  }
  await runInit({
    client: v.client as ClientKind | undefined, file: v.file, profile: v.profile,
    yes: v.yes ?? false, dryRun: v['dry-run'] ?? false, cwd: process.cwd(), paths: resolvePaths(),
  }, io);
  return 0;
}

async function cmdUninstall(args: string[]): Promise<number> {
  const v = parse(args, { profile: { type: 'string' }, yes: { type: 'boolean' }, 'dry-run': { type: 'boolean' } });
  if (!v.profile) throw new UserError('Pass --profile <name>.', 'See installed profiles with `mcphantom doctor`.');
  if (!PROFILE_NAME_RE.test(v.profile)) throw new UserError(`Invalid profile name: ${v.profile}`);
  await runUninstall({ profile: v.profile, yes: v.yes ?? false, dryRun: v['dry-run'] ?? false, paths: resolvePaths() }, io);
  return 0;
}

async function cmdSuggest(args: string[]): Promise<number> {
  const v = parse(args, { profile: { type: 'string' }, config: { type: 'string' }, write: { type: 'boolean' }, 'accept-loose': { type: 'boolean' } });
  const paths = resolvePaths();
  return runSuggest({ configFile: resolveConfigFile(paths, v).file, paths, write: v.write ?? false, acceptLoose: v['accept-loose'] ?? false }, io);
}

async function cmdPolicy(args: string[]): Promise<number> {
  const [sub, ...rest] = args;
  const paths = resolvePaths();
  if (sub === 'lint') {
    const v = parse(rest, { profile: { type: 'string' }, config: { type: 'string' } });
    return runPolicyLint(resolveConfigFile(paths, v).file, paths, io);
  }
  if (sub === 'test') {
    const v = parse(rest, { profile: { type: 'string' }, config: { type: 'string' }, fixtures: { type: 'string' } });
    if (!v.fixtures) throw new UserError('Pass --fixtures <file.yaml>.');
    return runPolicyTest(resolveConfigFile(paths, v).file, path.resolve(v.fixtures), io);
  }
  if (sub === 'explain') {
    const v = parse(rest, { profile: { type: 'string' }, config: { type: 'string' }, tool: { type: 'string' }, arg: { type: 'string', multiple: true }, context: { type: 'string' } });
    if (!v.tool) throw new UserError('Pass --tool <server>__<tool>.');
    const argObj: Record<string, unknown> = {};
    for (const kv of (v.arg as string[] | undefined) ?? []) {
      const eq = kv.indexOf('=');
      if (eq < 0) throw new UserError(`--arg must be key=value, got '${kv}'`);
      argObj[kv.slice(0, eq)] = kv.slice(eq + 1);
    }
    const ctx: Label = contextFromFlag(v.context);
    return runPolicyExplain(resolveConfigFile(paths, v).file, v.tool, argObj, ctx, io);
  }
  throw new UserError(`Unknown policy subcommand: ${sub ?? '(none)'}`, 'Usage: mcphantom policy (lint | test --fixtures <f> | explain --tool <t> [--arg k=v] [--context untrusted/secret])');
}

function contextFromFlag(flag: string | undefined): Label {
  if (!flag) return BOTTOM;
  const [integrity, confidentiality] = flag.split('/');
  return {
    integrity: integrity === 'untrusted' ? 'untrusted' : 'trusted',
    confidentiality: confidentiality === 'secret' ? 'secret' : confidentiality === 'internal' ? 'internal' : 'public',
  };
}

async function cmdApprove(args: string[]): Promise<number> {
  const v = parse(args, { profile: { type: 'string' }, config: { type: 'string' }, yes: { type: 'boolean' } });
  const paths = resolvePaths();
  const { file } = resolveConfigFile(paths, v);
  await runApprove({ configFile: file, paths, yes: v.yes ?? false }, io);
  return 0;
}

async function cmdLock(args: string[]): Promise<number> {
  const [sub, ...rest] = args;
  if (sub !== 'diff') throw new UserError(`Unknown lock subcommand: ${sub ?? '(none)'}`, 'Usage: mcphantom lock diff [--config <file> | --profile <name>]');
  const v = parse(rest, { profile: { type: 'string' }, config: { type: 'string' } });
  const paths = resolvePaths();
  const { file } = resolveConfigFile(paths, v);
  return runLockDiff({ configFile: file, paths }, io);
}

function cmdTrace(args: string[]): number {
  const v = parse(args, { session: { type: 'string' }, config: { type: 'string' }, 'data-dir': { type: 'string' }, last: { type: 'boolean' }, json: { type: 'boolean' } });
  const paths = resolvePaths();
  let dataDir = v['data-dir'];
  if (!dataDir && v.config) {
    const file = path.resolve(v.config);
    const cfg = loadConfigFile(file).config;
    if (cfg.data_dir) dataDir = path.resolve(path.dirname(file), cfg.data_dir);
  }
  return runTrace({ dataDir, sessionId: v.session, last: v.last ?? false, json: v.json ?? false, paths }, out);
}

function cmdDoctor(args: string[]): number {
  const v = parse(args, { profile: { type: 'string' }, config: { type: 'string' } });
  const paths = resolvePaths();
  out(`MCPhantom ${VERSION}, Node ${process.version}, ${process.platform}/${process.arch}`);
  out(`config dir: ${paths.configDir}`);
  out(`data dir:   ${paths.dataDir}`);
  let problems = 0;
  for (const p of [paths.configDir, paths.profilesDir, paths.dataDir, path.join(paths.dataDir, 'events.db')]) {
    if (!fs.existsSync(p)) continue;
    const c = checkPrivate(p);
    if (!c.ok) {
      problems += c.problems.length;
      for (const pr of c.problems) out(`  ✗ ${pr}`);
    }
  }
  if (fs.existsSync(paths.profilesDir)) {
    const profiles = fs.readdirSync(paths.profilesDir).filter((f) => f.endsWith('.yaml'));
    out(`profiles: ${profiles.length ? profiles.map((f) => f.replace(/\.yaml$/, '')).join(', ') : '(none)'}`);
  } else {
    out('profiles: (none — run `mcphantom init`)');
  }
  if (v.profile || v.config) {
    const { file } = resolveConfigFile(paths, v);
    const loaded = loadConfigFile(file);
    out(`config ${file}: valid, ${Object.keys(loaded.config.servers).length} server(s): ${Object.keys(loaded.config.servers).join(', ')}`);
    const c = checkPrivate(file);
    if (!c.ok) {
      problems += c.problems.length;
      for (const pr of c.problems) out(`  ✗ ${pr}`);
    }
  }
  out(problems === 0 ? 'permissions: ok' : `permissions: ${problems} problem(s) (\`mcphantom run\` fixes these by default)`);
  return problems === 0 ? 0 : 2;
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    if (err instanceof UserError) {
      console.error(`mcphantom: ${err.message}`);
      if (err.hint) console.error(err.hint);
      process.exitCode = 2;
    } else {
      console.error(`mcphantom: unexpected error: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}`);
      process.exitCode = 1;
    }
  },
);
