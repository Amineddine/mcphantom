import { UserError } from '../util/errors.js';

/**
 * Expands `${VAR}` and `${VAR:-default}` the same way Claude Code expands `.mcp.json`, so that
 * server entries moved out of a client config by `mcphantom init` keep working unchanged.
 * `$$` is not special; there is no recursive expansion (expanded values are never re-scanned).
 */
const VAR_RE = /\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}/g;

export function expandEnv(value: string, env: NodeJS.ProcessEnv, where: string): string {
  return value.replace(VAR_RE, (_m, name: string, fallback: string | undefined) => {
    const v = env[name];
    if (v !== undefined && v !== '') return v;
    if (fallback !== undefined) return fallback;
    throw new UserError(
      `Environment variable ${name} is not set (referenced in ${where}).`,
      `Set ${name}, or give a default with \${${name}:-value}.`,
    );
  });
}
