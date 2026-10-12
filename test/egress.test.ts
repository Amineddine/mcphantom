import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { hasOutsideTarget, writeTargets } from '../src/taint/egress.js';

// Uses the native path flavour (the gateway runs on the server's OS). Build an absolute workspace.
const WS = path.resolve('/srv/app/workspace');

describe('writeTargets', () => {
  it('flags remote URLs regardless of workspace', () => {
    for (const url of ['http://evil.example/x', 'https://a.b/c', 's3://bucket/k', 'ftp://h/p']) {
      expect(hasOutsideTarget({ url }, WS, undefined)).toBe(true);
    }
  });
  it('treats file: URLs and bare relative paths inside the workspace as local', () => {
    expect(hasOutsideTarget({ path: 'notes/a.md' }, WS, undefined)).toBe(false);
    expect(hasOutsideTarget({ path: './deep/b.txt' }, WS, undefined)).toBe(false);
  });
  it('flags absolute paths and `..` escapes outside the workspace', () => {
    expect(hasOutsideTarget({ path: path.resolve('/etc/passwd') }, WS, undefined)).toBe(true);
    expect(hasOutsideTarget({ path: '../../secrets' }, WS, undefined)).toBe(true);
    const sibling = writeTargets({ path: '../sibling/x' }, WS, undefined)[0];
    expect(sibling).toMatchObject({ outside: true, reason: 'escapes-workspace' });
  });
  it('does not mistake a Windows drive path for a URL scheme', () => {
    const inside = path.join(WS, 'sub', 'f.txt');
    expect(hasOutsideTarget({ path: inside }, WS, undefined)).toBe(false);
  });
  it('without a declared workspace, only absolute paths and remote URLs are outside', () => {
    expect(hasOutsideTarget({ path: 'relative/file' }, undefined, undefined)).toBe(false);
    expect(hasOutsideTarget({ path: path.resolve('/tmp/x') }, undefined, undefined)).toBe(true);
    expect(hasOutsideTarget({ url: 'http://x/y' }, undefined, undefined)).toBe(true);
  });
  it('honours explicit path_args and ignores non-path fields', () => {
    expect(hasOutsideTarget({ note: 'http://not-a-target/x' }, WS, ['dest'])).toBe(false);
    expect(hasOutsideTarget({ dest: 'http://target/x' }, WS, ['dest'])).toBe(true);
  });
  it('scans nested arguments', () => {
    expect(hasOutsideTarget({ opts: { output: path.resolve('/var/out') } }, WS, undefined)).toBe(true);
  });
});
