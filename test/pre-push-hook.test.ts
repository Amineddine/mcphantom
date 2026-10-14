/**
 * The versioned pre-push hook (.githooks/pre-push). Owner process fix (6b PR 4): a failing check's full
 * output is written to <git-dir>/mcphantom-pre-push.log and its path printed, so it is never lost.
 * Runs the real hook in a throwaway repository with a fake `npm` first on PATH.
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { ROOT, tempDir } from './helpers.js';

const sh = spawnSync('sh', ['-c', 'exit 0']).status === 0;
const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});

function repo(npmScript: string): { dir: string; run: () => { status: number | null; stderr: string } } {
  const dir = tempDir('mcphantom-hook-');
  dirs.push(dir);
  const git = (...a: string[]) => spawnSync('git', a, { cwd: dir, encoding: 'utf8' });
  git('init', '-q');
  git('config', 'user.email', 'test@example.invalid');
  git('config', 'user.name', 'test');
  fs.writeFileSync(path.join(dir, 'a.txt'), 'a\n');
  git('add', '.');
  git('commit', '-q', '-m', 'init');
  const bin = path.join(dir, '.fakebin');
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'npm'), `#!/bin/sh\n${npmScript}\n`, { mode: 0o755 });
  const hook = path.join(ROOT, '.githooks', 'pre-push');
  return {
    dir,
    run: () => {
      const r = spawnSync('sh', [hook], { cwd: dir, encoding: 'utf8', env: { ...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH ?? ''}` } });
      return { status: r.status, stderr: r.stderr };
    },
  };
}
const logOf = (dir: string) => fs.readFileSync(path.join(dir, '.git', 'mcphantom-pre-push.log'), 'utf8');

describe.skipIf(!sh)('pre-push hook', () => {
  it('a failing check blocks the push, keeps the full output in the log, and prints its path', () => {
    const lines = Array.from({ length: 100 }, (_, i) => `echo "line ${i}"`).join('\n');
    const r = repo(`${lines}\necho "FAIL test/x.test.ts > something broke"\nexit 1`);
    const out = r.run();
    expect(out.status).toBe(1);
    expect(out.stderr).toMatch(/full output: .*mcphantom-pre-push\.log/);
    expect(out.stderr).toContain('something broke'); // the tail is shown
    const log = logOf(r.dir);
    expect(log).toContain('line 0'); // the whole output, not only the tail
    expect(log).toContain('FAIL test/x.test.ts > something broke');
    expect(log).toContain('exit status: 1');
  });

  it('a passing check lets the push through and overwrites the previous log', () => {
    const r = repo('echo "      Tests  3 passed (3)"');
    fs.writeFileSync(path.join(r.dir, '.git', 'mcphantom-pre-push.log'), 'stale content from an earlier run\n');
    const out = r.run();
    expect(out.status).toBe(0);
    expect(out.stderr).toContain('check passed');
    expect(logOf(r.dir)).not.toContain('stale content');
    expect(logOf(r.dir)).toContain('exit status: 0');
  });

  it('a dirty tree is refused before the check runs, and the refusal is logged too', () => {
    const r = repo('echo should-not-run');
    fs.writeFileSync(path.join(r.dir, 'a.txt'), 'changed\n');
    const out = r.run();
    expect(out.status).toBe(1);
    expect(out.stderr).toMatch(/uncommitted changes/);
    expect(logOf(r.dir)).toMatch(/uncommitted changes/);
    expect(logOf(r.dir)).not.toContain('should-not-run');
  });
});
