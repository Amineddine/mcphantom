import path from 'node:path';
import type { Prompt, Tool } from '@modelcontextprotocol/sdk/types.js';
import { loadConfigFile } from '../config/load.js';
import type { Paths } from '../config/paths.js';
import { Gateway } from '../gateway/gateway.js';
import { RugpullChecker } from '../rugpull/checker.js';
import { schemaArgNames } from '../policy/lint.js';
import { SqliteStore } from '../store/store.js';
import { silentLogger, type Logger } from '../util/log.js';
import { VERSION } from '../version.js';

export interface LiveDefinitions {
  tools: Record<string, Tool[]>;
  prompts: Record<string, Prompt[]>;
  instructions: Record<string, string | undefined>;
  close: () => Promise<void>;
}

/**
 * Connects every upstream once and returns its current definitions. Scanning and rug-pull enforcement
 * are off: this inspects raw definitions, it does not serve them to a model.
 */
export async function collectLive(configFile: string, paths: Paths, logger: Logger = silentLogger): Promise<LiveDefinitions> {
  const loaded = loadConfigFile(configFile);
  const dataDir = loaded.config.data_dir ? path.resolve(path.dirname(configFile), loaded.config.data_dir) : paths.dataDir;
  const store = new SqliteStore({
    dataDir, payloads: 'none', maxPayloadBytes: 65_536, retentionDays: 36_500, retentionMaxMb: 1_000_000,
    knownSecrets: loaded.secrets, insecurePermissions: 'warn', logger,
  });
  const sessionId = `inspect-${Date.now().toString(36)}`;
  store.startSession({ id: sessionId });
  const config = { ...loaded.config, scan: { ...loaded.config.scan, enabled: false } };
  const gw = await Gateway.create({ config, store, logger, sessionId, version: VERSION, rugpull: new RugpullChecker(undefined, false) });
  const tools: Record<string, Tool[]> = {};
  const prompts: Record<string, Prompt[]> = {};
  const instructions: Record<string, string | undefined> = {};
  for (const [id, u] of gw.upstreams) {
    if (!u.ready) continue;
    instructions[id] = u.instructions;
    tools[id] = await u.listTools();
    if (u.capabilities.prompts) prompts[id] = await u.listPrompts();
  }
  return { tools, prompts, instructions, close: async () => { await gw.close(); store.close(); } };
}

/** Arg-name sets keyed by exposed tool name (`<serverId>__<tool>`), for the policy linter. */
export async function collectSchemas(configFile: string, paths: Paths): Promise<Map<string, Set<string>>> {
  const live = await collectLive(configFile, paths);
  try {
    const out = new Map<string, Set<string>>();
    for (const [serverId, tools] of Object.entries(live.tools)) {
      for (const t of tools) out.set(`${serverId}__${t.name}`, schemaArgNames(t.inputSchema));
    }
    return out;
  } finally {
    await live.close();
  }
}
