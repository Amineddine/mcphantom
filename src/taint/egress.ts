import path from 'node:path';

/**
 * A `write` tool is exfiltration in disguise when its target is not inside the declared workspace:
 * a remote URL, or a filesystem path that escapes the workspace (an absolute path elsewhere, a `..`
 * escape, or a path into a synced/pushed folder the workspace does not cover). Such a write is treated
 * as `egress` by the trifecta invariant until the policy engine (Phase 4) can express per-target rules.
 *
 * This is a lexical check only — it never touches the filesystem (the path may not exist, and the
 * gateway must not stat arbitrary paths). Symlink escapes inside the workspace are therefore not
 * caught here; that is the sandbox's job (DESIGN.md threat model).
 */

/** Argument names commonly naming a write destination, matched case-insensitively. */
const PATH_ARG_RE = /^(?:path|file|filename|filepath|dest|destination|target|output|out|to|uri|url|location|key)$/i;

export interface WriteTarget {
  argPath: string;
  value: string;
  outside: boolean;
  reason: 'remote-url' | 'absolute-outside' | 'escapes-workspace' | 'inside';
}

/** Collects destination-like leaves of the arguments and classifies each against the workspace. */
export function writeTargets(args: unknown, workspaceRoot: string | undefined, explicitPathArgs: readonly string[] | undefined): WriteTarget[] {
  const out: WriteTarget[] = [];
  const want = explicitPathArgs && explicitPathArgs.length > 0 ? new Set(explicitPathArgs.map((s) => s.toLowerCase())) : undefined;
  for (const [key, value, argPath] of stringLeaves(args)) {
    const named = want ? want.has(key.toLowerCase()) : PATH_ARG_RE.test(key);
    if (!named) continue;
    out.push({ argPath, value, ...classifyTarget(value, workspaceRoot) });
  }
  return out;
}

export function hasOutsideTarget(args: unknown, workspaceRoot: string | undefined, explicitPathArgs: readonly string[] | undefined): boolean {
  return writeTargets(args, workspaceRoot, explicitPathArgs).some((t) => t.outside);
}

function classifyTarget(value: string, workspaceRoot: string | undefined): { outside: boolean; reason: WriteTarget['reason'] } {
  // A parseable non-file URL with a host is a remote destination.
  const scheme = /^([a-z][a-z0-9+.-]*):/i.exec(value);
  if (scheme && scheme[1] && scheme[1].toLowerCase() !== 'file') {
    // Windows drive letters ("C:\...") parse as a scheme; treat single-letter schemes as paths.
    if (scheme[1].length > 1) return { outside: true, reason: 'remote-url' };
  }
  if (workspaceRoot === undefined) {
    // No declared safe zone: a bare relative name is assumed local; anything absolute is outside.
    return path.isAbsolute(value) ? { outside: true, reason: 'absolute-outside' } : { outside: false, reason: 'inside' };
  }
  const root = path.resolve(workspaceRoot);
  const target = path.resolve(root, value);
  const rel = path.relative(root, target);
  if (rel === '') return { outside: false, reason: 'inside' };
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    return { outside: true, reason: path.isAbsolute(value) ? 'absolute-outside' : 'escapes-workspace' };
  }
  return { outside: false, reason: 'inside' };
}

function stringLeaves(v: unknown, keyPath: string[] = [], jsonPath = '$', out: [string, string, string][] = [], depth = 0): [string, string, string][] {
  if (depth > 32) return out;
  if (typeof v === 'string') {
    out.push([keyPath[keyPath.length - 1] ?? '', v, jsonPath]);
  } else if (Array.isArray(v)) {
    v.forEach((x, i) => stringLeaves(x, keyPath, `${jsonPath}[${i}]`, out, depth + 1));
  } else if (v && typeof v === 'object') {
    for (const [k, x] of Object.entries(v)) stringLeaves(x, [...keyPath, k], `${jsonPath}.${k}`, out, depth + 1);
  }
  return out;
}
