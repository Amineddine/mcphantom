import fs from 'node:fs';
import path from 'node:path';
import { parseDocument } from 'yaml';
import { z } from 'zod';
import { UserError } from '../util/errors.js';
import { expandEnv } from './env.js';
import { ConfigSchema, type Config, type ServerConfig } from './schema.js';

export interface LoadedConfig {
  path: string;
  config: Config;
  /** Values that must never appear in logs: expanded env values and headers of upstream servers. */
  secrets: string[];
}

export function loadConfigFile(file: string, env: NodeJS.ProcessEnv = process.env): LoadedConfig {
  const abs = path.resolve(file);
  let text: string;
  try {
    text = fs.readFileSync(abs, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      throw new UserError(`Config file not found: ${abs}`, 'Run `mcphantom init` to create one from your MCP client config.');
    }
    throw err;
  }
  return parseConfig(text, abs, env);
}

export function parseConfig(text: string, where: string, env: NodeJS.ProcessEnv = process.env): LoadedConfig {
  const doc = parseDocument(text, { prettyErrors: true, uniqueKeys: true });
  if (doc.errors.length > 0) {
    throw new UserError(`Invalid YAML in ${where}:\n${doc.errors.map((e) => '  ' + e.message).join('\n')}`);
  }
  const raw: unknown = doc.toJS({ maxAliasCount: 50 });
  const parsed = ConfigSchema.safeParse(raw);
  if (!parsed.success) {
    throw new UserError(`Invalid config in ${where}:\n${formatZodError(parsed.error)}`);
  }
  const config = parsed.data;
  const secrets: string[] = [];
  for (const [id, server] of Object.entries(config.servers)) {
    config.servers[id] = expandServer(server, env, `${where} → servers.${id}`, secrets);
  }
  return { path: where, config, secrets };
}

function expandServer(s: ServerConfig, env: NodeJS.ProcessEnv, where: string, secrets: string[]): ServerConfig {
  if (s.type === 'stdio') {
    const e: Record<string, string> = {};
    for (const [k, v] of Object.entries(s.env)) {
      e[k] = expandEnv(v, env, `${where}.env.${k}`);
      secrets.push(e[k]);
    }
    const out: ServerConfig = {
      ...s,
      command: expandEnv(s.command, env, `${where}.command`),
      args: s.args.map((a, i) => expandEnv(a, env, `${where}.args[${i}]`)),
      env: e,
    };
    if (s.cwd !== undefined) out.cwd = expandEnv(s.cwd, env, `${where}.cwd`);
    return out;
  }
  const h: Record<string, string> = {};
  for (const [k, v] of Object.entries(s.headers)) {
    h[k] = expandEnv(v, env, `${where}.headers.${k}`);
    secrets.push(h[k]);
  }
  const url = expandEnv(s.url, env, `${where}.url`);
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url);
  } catch {
    throw new UserError(`Invalid URL in ${where}.url: ${url}`);
  }
  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    throw new UserError(`Unsupported URL scheme in ${where}.url: ${parsedUrl.protocol} (only http and https)`);
  }
  return { ...s, url, headers: h };
}

export function formatZodError(err: z.ZodError): string {
  return err.issues
    .map((i) => {
      const where = i.path.length > 0 ? i.path.join('.') : '(root)';
      // Record-key failures wrap the useful message ("server ids must match ...") one level down.
      const inner = i.code === 'invalid_key' ? i.issues.map((x) => x.message).join('; ') : undefined;
      return `  - ${where}: ${inner ?? i.message}`;
    })
    .join('\n');
}
