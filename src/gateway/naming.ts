import { SERVER_ID_RE } from '../config/schema.js';

export const SEPARATOR = '__';

/** Tool/prompt names exposed downstream must satisfy the MCP naming guidance (SEP-986). */
const EXPOSED_NAME_RE = /^[A-Za-z0-9_.-]{1,128}$/;

export function exposeName(serverId: string, name: string): string | undefined {
  const exposed = `${serverId}${SEPARATOR}${name}`;
  return EXPOSED_NAME_RE.test(exposed) ? exposed : undefined;
}

/** Splits an exposed name at the first separator. Server ids never contain `_`, so this is unambiguous. */
export function parseExposedName(exposed: string): { serverId: string; name: string } | undefined {
  const i = exposed.indexOf(SEPARATOR);
  if (i <= 0) return undefined;
  const serverId = exposed.slice(0, i);
  const name = exposed.slice(i + SEPARATOR.length);
  if (!SERVER_ID_RE.test(serverId) || name.length === 0) return undefined;
  return { serverId, name };
}
