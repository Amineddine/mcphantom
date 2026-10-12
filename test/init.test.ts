import fs from 'node:fs';
import path from 'node:path';
import { parse } from 'yaml';
import { afterEach, describe, expect, it } from 'vitest';
import { convertEntries, isGatewayEntry, uniqueId } from '../src/clients/clients.js';
import { formatLike, originPath, runInit, runUninstall, type Io } from '../src/cli/init.js';
import { parseConfig } from '../src/config/load.js';
import { profilePath, resolvePaths } from '../src/config/paths.js';
import { checkPrivate } from '../src/security/fileperms.js';
import { tempDir } from './helpers.js';

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});

function setup(clientConfig: unknown, raw?: string) {
  const root = tempDir();
  dirs.push(root);
  const paths = resolvePaths({ MCPHANTOM_HOME: path.join(root, 'home') });
  const file = path.join(root, 'project', '.mcp.json');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, raw ?? JSON.stringify(clientConfig, null, 4) + '\n');
  const lines: string[] = [];
  const io: Io = { out: (t) => lines.push(t), confirm: () => Promise.resolve(true) };
  return { root, paths, file, io, lines };
}

const GW = { command: '/abs/node', args: ['/abs/mcphantom/dist/cli/main.js'] };

const original = {
  theme: 'dark',
  mcpServers: {
    filesystem: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/work'], env: { DEBUG: '1' } },
    'GitHub Server': { command: 'npx', args: ['gh-mcp'], env: { GITHUB_TOKEN: '${GITHUB_TOKEN}' } },
    remote: { type: 'http', url: 'https://mcp.example.com/mcp', headers: { Authorization: 'Bearer ${TOKEN}' } },
    legacy: { type: 'sse', url: 'https://old.example.com/sse' },
    off: { command: 'x', disabled: true },
  },
};

describe('convertEntries', () => {
  it('moves stdio and http entries, leaves SSE/disabled/unknown with a reason', () => {
    const r = convertEntries(original.mcpServers);
    expect(Object.keys(r.servers)).toEqual(['filesystem', 'github-server', 'remote']);
    expect(r.servers.remote).toEqual({ type: 'http', url: 'https://mcp.example.com/mcp', headers: { Authorization: 'Bearer ${TOKEN}' } });
    expect(r.skipped.map((s) => s.name)).toEqual(['legacy', 'off']);
    expect(r.skipped[0]?.reason).toMatch(/NOT protected/);
  });

  it('derives valid unique ids', () => {
    const used = new Set<string>();
    const ids = ['My Server', 'my-server', '123abc', '!!!', 'a'.repeat(50)].map((n) => {
      const id = uniqueId(n, used);
      used.add(id);
      return id;
    });
    expect(ids).toEqual(['my-server', 'my-server-2', 'abc', 'server', 'a'.repeat(28)]);
  });

  it('recognises an existing gateway entry', () => {
    expect(isGatewayEntry({ command: '/n/node', args: ['/x/mcphantom/dist/cli/main.js', 'run', '--profile', 'p'] })).toBe(true);
    expect(isGatewayEntry({ command: 'npx', args: ['mcphantom-lookalike'] })).toBe(false);
  });
});

describe('init / uninstall', () => {
  it('rewrites the client config, writes an owner-only profile, and round-trips on uninstall', async () => {
    const { paths, file, io } = setup(original);
    const before = fs.readFileSync(file, 'utf8');
    await runInit({ file, profile: 'proj', yes: true, dryRun: false, cwd: path.dirname(file), paths, gatewayCommand: GW }, io);

    const after = JSON.parse(fs.readFileSync(file, 'utf8')) as typeof original & { mcpServers: Record<string, unknown> };
    expect(after.theme).toBe('dark'); // unrelated keys preserved
    expect(Object.keys(after.mcpServers).sort()).toEqual(['legacy', 'mcphantom', 'off']);
    expect(after.mcpServers.mcphantom).toEqual({ command: '/abs/node', args: ['/abs/mcphantom/dist/cli/main.js', 'run', '--profile', 'proj'] });
    expect(fs.readFileSync(file, 'utf8')).toMatch(/^\{\n {4}"theme"/); // original 4-space indent kept

    const pPath = profilePath(paths, 'proj');
    const profile = parse(fs.readFileSync(pPath, 'utf8')) as { servers: Record<string, unknown> };
    expect(Object.keys(profile.servers)).toEqual(['filesystem', 'github-server', 'remote']);
    expect(checkPrivate(pPath).ok).toBe(true);
    expect(checkPrivate(originPath(paths, 'proj')).ok).toBe(true);
    // The generated profile loads with the same ${VAR} semantics the client used.
    const loaded = parseConfig(fs.readFileSync(pPath, 'utf8'), pPath, { GITHUB_TOKEN: 'placeholder', TOKEN: 't' });
    expect(loaded.config.servers['github-server']).toMatchObject({ env: { GITHUB_TOKEN: 'placeholder' } });

    // Backups exist, are owner-only, and contain the original bytes.
    const backups = fs.readdirSync(path.join(paths.configDir, 'backups'));
    expect(backups).toHaveLength(1);
    const backup = path.join(paths.configDir, 'backups', backups[0] as string);
    expect(fs.readFileSync(backup, 'utf8')).toBe(before);
    expect(checkPrivate(backup).ok).toBe(true);

    await runUninstall({ profile: 'proj', yes: true, dryRun: false, paths }, io);
    expect(JSON.parse(fs.readFileSync(file, 'utf8'))).toEqual(original);
    expect(fs.existsSync(originPath(paths, 'proj'))).toBe(false);
  });

  it('is idempotent: a second init finds nothing to move', async () => {
    const { paths, file, io, lines } = setup(original);
    await runInit({ file, profile: 'p1', yes: true, dryRun: false, cwd: '.', paths, gatewayCommand: GW }, io);
    const snapshot = fs.readFileSync(file, 'utf8');
    await runInit({ file, profile: 'p2', yes: true, dryRun: false, cwd: '.', paths, gatewayCommand: GW }, io);
    expect(fs.readFileSync(file, 'utf8')).toBe(snapshot);
    expect(lines.join('\n')).toMatch(/already the MCPhantom gateway/);
    expect(lines.join('\n')).toMatch(/Nothing to do/);
  });

  it('dry run writes nothing', async () => {
    const { paths, file, io, lines } = setup(original);
    const before = fs.readFileSync(file, 'utf8');
    await runInit({ file, profile: 'p', yes: true, dryRun: true, cwd: '.', paths, gatewayCommand: GW }, io);
    expect(fs.readFileSync(file, 'utf8')).toBe(before);
    expect(fs.existsSync(paths.configDir)).toBe(false);
    expect(lines.join('\n')).toMatch(/^\+ +"mcphantom": \{/m);
  });

  it('declining the confirmation writes nothing', async () => {
    const { paths, file, lines } = setup(original);
    const before = fs.readFileSync(file, 'utf8');
    await runInit({ file, profile: 'p', yes: false, dryRun: false, cwd: '.', paths, gatewayCommand: GW }, { out: (t) => lines.push(t), confirm: () => Promise.resolve(false) });
    expect(fs.readFileSync(file, 'utf8')).toBe(before);
    expect(fs.existsSync(profilePath(paths, 'p'))).toBe(false);
  });

  it('refuses to clobber a client config edited concurrently', async () => {
    const { paths, file } = setup(original);
    const io: Io = {
      out: () => {},
      confirm: () => {
        fs.writeFileSync(file, JSON.stringify({ mcpServers: { edited: { command: 'y' } } }));
        return Promise.resolve(true);
      },
    };
    await expect(runInit({ file, profile: 'p', yes: false, dryRun: false, cwd: '.', paths, gatewayCommand: GW }, io)).rejects.toThrow(/changed while MCPhantom/);
    expect(JSON.parse(fs.readFileSync(file, 'utf8'))).toEqual({ mcpServers: { edited: { command: 'y' } } });
  });

  it('gives a clear error for invalid JSON and refuses a reused profile', async () => {
    const bad = setup(undefined, '{ "mcpServers": { ');
    await expect(runInit({ file: bad.file, profile: 'p', yes: true, dryRun: false, cwd: '.', paths: bad.paths, gatewayCommand: GW }, bad.io)).rejects.toThrow(/not valid JSON/);

    const { paths, file, io } = setup(original);
    await runInit({ file, profile: 'same', yes: true, dryRun: false, cwd: '.', paths, gatewayCommand: GW }, io);
    fs.writeFileSync(file, JSON.stringify(original));
    await expect(runInit({ file, profile: 'same', yes: true, dryRun: false, cwd: '.', paths, gatewayCommand: GW }, io)).rejects.toThrow(/already installed/);
  });

  it('uninstall keeps entries the user added since, and does not overwrite a re-added server', async () => {
    const { paths, file, io } = setup(original);
    await runInit({ file, profile: 'p', yes: true, dryRun: false, cwd: '.', paths, gatewayCommand: GW }, io);
    const cur = JSON.parse(fs.readFileSync(file, 'utf8')) as { mcpServers: Record<string, unknown> };
    cur.mcpServers.newone = { command: 'new' };
    cur.mcpServers.filesystem = { command: 'user-edited' };
    fs.writeFileSync(file, JSON.stringify(cur, null, 2));
    await runUninstall({ profile: 'p', yes: true, dryRun: false, paths }, io);
    const restored = JSON.parse(fs.readFileSync(file, 'utf8')) as { mcpServers: Record<string, unknown> };
    expect(restored.mcpServers.newone).toEqual({ command: 'new' });
    expect(restored.mcpServers.filesystem).toEqual({ command: 'user-edited' });
    expect(restored.mcpServers.remote).toEqual(original.mcpServers.remote);
    expect(restored.mcpServers.mcphantom).toBeUndefined();
  });
});

describe('formatLike', () => {
  it('keeps tabs and the absence of a trailing newline', () => {
    expect(formatLike('{\n\t"a": 1\n}', { a: 2 })).toBe('{\n\t"a": 2\n}');
  });
});
