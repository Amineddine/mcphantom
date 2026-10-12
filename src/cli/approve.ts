import { loadConfigFile } from '../config/load.js';
import type { Paths } from '../config/paths.js';
import { definitionOf, pinsFrom, promptDefinitionOf } from '../rugpull/checker.js';
import { fingerprint } from '../rugpull/canonical.js';
import { loadLockfile, lockPathFor, saveLockfile, type LockfileData } from '../rugpull/lockfile.js';
import { lintPolicy, schemaArgNames } from '../policy/lint.js';
import { reportLint } from './policy.js';
import { collectLive } from './schemas.js';
import { UserError } from '../util/errors.js';

export interface ApproveIo {
  out(text: string): void;
  confirm(question: string): Promise<boolean>;
}

export interface ApproveOptions {
  configFile: string;
  paths: Paths;
  yes: boolean;
}

export async function runApprove(opts: ApproveOptions, io: ApproveIo): Promise<void> {
  const existing = loadLockfile(opts.configFile, opts.paths.configDir);
  const live = await collectLive(opts.configFile, opts.paths);
  try {
    const next = pinsFrom(live.tools, live.prompts, live.instructions);
    const diff = diffLock(existing.integrity === 'empty' ? undefined : existing.data, next);
    io.out(`Lockfile: ${lockPathFor(opts.configFile)}`);
    if (existing.integrity === 'bad-signature') io.out('  ! existing lockfile failed HMAC verification; it will be replaced.');
    printDiff(diff, io);
    const total = Object.values(next.servers).reduce((n, s) => n + Object.keys(s.tools).length + Object.keys(s.prompts).length, 0);
    if (diff.changed.length === 0 && diff.added.length === 0 && diff.removed.length === 0 && existing.integrity === 'ok') {
      io.out('Already up to date; nothing to approve.');
      return;
    }
    if (!opts.yes && !(await io.confirm(`Approve and pin ${total} definition(s) across ${Object.keys(next.servers).length} server(s)?`))) {
      io.out('Aborted; lockfile unchanged.');
      return;
    }
    const p = saveLockfile(opts.configFile, opts.paths.configDir, next);
    io.out(`Pinned. ${p}`);
    // Re-lint policy against the definitions we just approved (owner note #1).
    const schemas = new Map<string, Set<string>>();
    for (const [sid, tools] of Object.entries(live.tools)) for (const t of tools) schemas.set(`${sid}__${t.name}`, schemaArgNames(t.inputSchema));
    const issues = lintPolicy(loadConfigFile(opts.configFile).config, schemas);
    if (issues.length > 0) {
      io.out('Policy lint against the approved definitions:');
      reportLint(issues, io);
    }
  } finally {
    await live.close();
  }
}

export interface DiffOptions {
  configFile: string;
  paths: Paths;
}

export async function runLockDiff(opts: DiffOptions, io: ApproveIo): Promise<number> {
  const existing = loadLockfile(opts.configFile, opts.paths.configDir);
  if (existing.integrity === 'empty') {
    io.out(`No lockfile yet (${lockPathFor(opts.configFile)}). Run \`mcphantom approve\` to create one.`);
    return 1;
  }
  if (existing.integrity === 'bad-signature') io.out('! lockfile failed HMAC verification (tampered, or a different key/machine).');
  if (existing.integrity === 'missing-key') io.out('! HMAC key not found; cannot verify the lockfile signature.');
  if (existing.integrity === 'malformed') throw new UserError(`Lockfile ${lockPathFor(opts.configFile)} is malformed.`);
  const live = await collectLive(opts.configFile, opts.paths);
  try {
    const next = pinsFrom(live.tools, live.prompts, live.instructions);
    const diff = diffLock(existing.data, next);
    printDiff(diff, io);
    const drift = diff.changed.length + diff.added.length + diff.removed.length;
    if (drift === 0 && existing.integrity === 'ok') {
      io.out('Live definitions match the lockfile.');
      return 0;
    }
    return 2;
  } finally {
    await live.close();
  }
}

interface LockDiff {
  changed: string[];
  added: string[];
  removed: string[];
}

/** Compares two pin sets by fingerprint. `prev` undefined means a first approval (everything added). */
function diffLock(prev: LockfileData | undefined, next: LockfileData): LockDiff {
  const d: LockDiff = { changed: [], added: [], removed: [] };
  const entries = (data: LockfileData | undefined): Map<string, string> => {
    const m = new Map<string, string>();
    for (const [id, s] of Object.entries(data?.servers ?? {})) {
      if (s.instructions) m.set(`${id} instructions`, s.instructions);
      for (const [n, fp] of Object.entries(s.tools)) m.set(`${id}__${n} (tool)`, fp);
      for (const [n, fp] of Object.entries(s.prompts)) m.set(`${id}__${n} (prompt)`, fp);
    }
    return m;
  };
  const a = entries(prev);
  const b = entries(next);
  for (const [k, fp] of b) {
    if (!a.has(k)) d.added.push(k);
    else if (a.get(k) !== fp) d.changed.push(k);
  }
  for (const k of a.keys()) if (!b.has(k)) d.removed.push(k);
  d.changed.sort();
  d.added.sort();
  d.removed.sort();
  return d;
}

function printDiff(d: LockDiff, io: ApproveIo): void {
  if (d.changed.length === 0 && d.added.length === 0 && d.removed.length === 0) return;
  for (const k of d.changed) io.out(`  ~ changed: ${k}`);
  for (const k of d.added) io.out(`  + new:     ${k}`);
  for (const k of d.removed) io.out(`  - removed: ${k}`);
}

export { fingerprint, definitionOf, promptDefinitionOf };
