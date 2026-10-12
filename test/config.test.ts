import { describe, expect, it } from 'vitest';
import { expandEnv } from '../src/config/env.js';
import { parseConfig } from '../src/config/load.js';
import { resolvePaths } from '../src/config/paths.js';
import { exposeName, parseExposedName } from '../src/gateway/naming.js';
import { DEFAULT_PAGINATION, paginate } from '../src/gateway/upstream.js';
import { lineDiff } from '../src/util/diff.js';

describe('config', () => {
  it('applies defaults and infers server type', () => {
    const { config } = parseConfig('version: 1\nservers:\n  fs:\n    command: npx\n  web:\n    url: https://example.com/mcp\n', 'x.yaml', {});
    expect(config.servers.fs).toMatchObject({ type: 'stdio', args: [], env: {}, allow_sampling: false, env_inherit: 'minimal' });
    expect(config.servers.web).toMatchObject({ type: 'http', headers: {} });
    expect(config.logging.payloads).toBe('redacted');
    expect(config.security.insecure_permissions).toBe('fix');
  });

  it('expands ${VAR} and ${VAR:-default} and records expanded credentials as secrets', () => {
    const { config, secrets } = parseConfig(
      'version: 1\nservers:\n  gh:\n    command: ${BIN:-npx}\n    env:\n      TOKEN: ${GH_TOKEN}\n  api:\n    url: https://${HOST}/mcp\n    headers:\n      Authorization: Bearer ${API_KEY}\n',
      'x.yaml', { GH_TOKEN: 'ghtoken-value-123', HOST: 'api.example.com', API_KEY: 'k-123456789' },
    );
    expect(config.servers.gh).toMatchObject({ command: 'npx', env: { TOKEN: 'ghtoken-value-123' } });
    expect(config.servers.api).toMatchObject({ url: 'https://api.example.com/mcp' });
    expect(secrets).toEqual(expect.arrayContaining(['ghtoken-value-123', 'Bearer k-123456789']));
  });

  it.each([
    ['unknown keys (typos)', 'version: 1\nservers:\n  fs:\n    comand: npx\n', /comand|command/],
    ['bad server id', 'version: 1\nservers:\n  My_Server:\n    command: x\n', /server ids/],
    ['wrong version', 'version: 2\nservers: {}\n', /version/],
    ['non-http url scheme', 'version: 1\nservers:\n  a:\n    type: http\n    url: file:///etc/passwd\n', /Unsupported URL scheme/],
    ['missing env var', 'version: 1\nservers:\n  a:\n    command: ${NOPE}\n', /NOPE is not set/],
    ['duplicate keys', 'version: 1\nservers:\n  a:\n    command: x\n  a:\n    command: y\n', /Invalid YAML/],
    ['alias bomb', 'version: 1\na: &a [x,x,x,x,x,x,x,x,x,x]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a,*a]\nc: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b,*b]\nservers: {}\n', /./],
  ])('rejects %s with a helpful error', (_name, text, re) => {
    expect(() => parseConfig(text, 'bad.yaml', {})).toThrow(re);
  });

  it('does not re-expand expanded values', () => {
    expect(expandEnv('${A}', { A: '${B}', B: 'leak' }, 'x')).toBe('${B}');
  });

  it('honours MCPHANTOM_HOME', () => {
    const p = resolvePaths({ MCPHANTOM_HOME: '/tmp/mh' }, 'linux');
    expect(p.profilesDir.replace(/\\/g, '/')).toMatch(/\/tmp\/mh\/config\/profiles$/);
  });
});

describe('naming', () => {
  it('round-trips names, including names that contain the separator', () => {
    for (const name of ['read_file', 'a__b', '__x', 'x.y-z']) {
      const exposed = exposeName('fs', name);
      expect(exposed).toBeDefined();
      expect(parseExposedName(exposed as string)).toEqual({ serverId: 'fs', name });
    }
  });
  it('refuses names that would break MCP limits or charset', () => {
    expect(exposeName('fs', 'x'.repeat(125))).toBeUndefined();
    expect(exposeName('fs', 'has space')).toBeUndefined();
    expect(exposeName('fs', 'ünï')).toBeUndefined();
  });
  it('rejects exposed names without a valid server id', () => {
    for (const n of ['noseparator', '__tool', 'FS__tool', 'a_b__tool', 'fs__']) expect(parseExposedName(n)).toBeUndefined();
  });
});

describe('paginate', () => {
  it('collects all pages', async () => {
    const pages: Record<string, { items: number[]; nextCursor?: string }> = { '': { items: [1], nextCursor: 'b' }, b: { items: [2], nextCursor: 'c' }, c: { items: [3] } };
    expect(await paginate('s', 'x', DEFAULT_PAGINATION, (c) => Promise.resolve(pages[c ?? ''] ?? { items: [] }))).toEqual([1, 2, 3]);
  });
  it('fails on cycles, page and item limits', async () => {
    await expect(paginate('s', 'x', DEFAULT_PAGINATION, () => Promise.resolve({ items: [1], nextCursor: 'same' }))).rejects.toThrow(/repeated cursor/);
    let n = 0;
    await expect(paginate('s', 'x', { maxPages: 5, maxItems: 1000, maxBytes: 1e9 }, () => Promise.resolve({ items: [1], nextCursor: String(n++) }))).rejects.toThrow(/5 pages/);
    await expect(paginate('s', 'x', { maxPages: 5, maxItems: 3, maxBytes: 1e9 }, () => Promise.resolve({ items: [1, 2, 3, 4] }))).rejects.toThrow(/3 items/);
    await expect(paginate('s', 'x', { maxPages: 5, maxItems: 100, maxBytes: 50 }, () => Promise.resolve({ items: ['x'.repeat(60)] }))).rejects.toThrow(/50 bytes/);
  });
});

describe('lineDiff', () => {
  it('shows additions and removals with context', () => {
    const d = lineDiff('a\nb\nc', 'a\nB\nc');
    expect(d).toContain('- b');
    expect(d).toContain('+ B');
    expect(d).toContain('  a');
  });
});
