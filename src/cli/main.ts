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
import { runInit, runUninstall, type Io } from './init.js';

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
    insecurePermissions: cfg.security.insecure_permissions,
    logger,
  });
  const sessionId = crypto.randomUUID();
  store.startSession({ id: sessionId, profile });
  store.append({ sessionId, kind: 'session_start', payload: { version: VERSION, config: file, servers: Object.keys(cfg.servers) } });

  const gateway = await Gateway.create({ config: cfg, store, logger, sessionId, version: VERSION });
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
