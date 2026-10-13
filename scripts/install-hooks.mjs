// Points git at the versioned hooks in .githooks/ (run by `npm install` through the `prepare` script).
// Must never fail an install: outside this repository's own git checkout (e.g. a tarball install, or
// no git on PATH) it does nothing.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
try {
  if (!fs.existsSync(path.join(root, '.githooks', 'pre-push'))) process.exit(0);
  const top = execFileSync('git', ['rev-parse', '--show-toplevel'], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  if (path.resolve(top) !== root) process.exit(0); // installed inside some other repository: leave it alone
  execFileSync('git', ['config', 'core.hooksPath', '.githooks'], { cwd: root, stdio: 'ignore' });
  process.stdout.write('mcphantom: git hooks installed (core.hooksPath = .githooks; pre-push runs `npm run check`)\n');
} catch {
  // Not a git checkout, or git unavailable: nothing to install.
}
