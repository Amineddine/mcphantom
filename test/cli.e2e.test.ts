/**
 * End to end through real processes: an MCP client spawns `mcphantom run`, which spawns the fixture.
 * Set MCPHANTOM_E2E_DIST=1 to exercise the built `dist/` instead of the TypeScript sources.
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { stringify } from 'yaml';
import { checkPrivate } from '../src/security/fileperms.js';
import { fixtureServer, ROOT, tempDir, textOf, TSX_LOADER } from './helpers.js';

const useDist = process.env.MCPHANTOM_E2E_DIST === '1';
const cli = useDist
  ? { command: process.execPath, args: [path.join(ROOT, 'dist', 'cli', 'main.js')] }
  : { command: process.execPath, args: ['--import', TSX_LOADER, path.join(ROOT, 'src', 'cli', 'main.ts')] };

let home: string;
beforeAll(() => {
  home = tempDir();
});
afterAll(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

function runCli(args: string[], env: Record<string, string> = {}) {
  return spawnSync(cli.command, [...cli.args, ...args], { encoding: 'utf8', env: { ...process.env, MCPHANTOM_HOME: home, ...env }, timeout: 60_000 });
}

describe('mcphantom CLI', () => {
  it('prints its version and help', () => {
    const v = runCli(['--version']);
    expect(v.status).toBe(0);
    expect(v.stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
    expect(runCli(['--help']).stdout).toContain('mcphantom init');
  });

  it('fails with a helpful message and exit code 2 on user errors', () => {
    const r = runCli(['run', '--profile', 'does-not-exist']);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('Config file not found');
    expect(r.stderr).toContain('mcphantom init');
    expect(r.stdout).toBe('');
    const u = runCli(['frobnicate']);
    expect(u.status).toBe(2);
    expect(u.stderr).toContain('Unknown command');
  });

  it('runs as a stdio gateway for a real MCP client, logs to stderr only, and hardens its files', async () => {
    const cfgFile = path.join(home, 'gw.yaml');
    fs.writeFileSync(cfgFile, stringify({ version: 1, servers: { fx: fixtureServer('everything', { env: { FIXTURE_SECRET: 'e2e-secret-value-42' } }) } }));
    const client = new Client({ name: 'e2e', version: '1' });
    const transport = new StdioClientTransport({
      command: cli.command,
      args: [...cli.args, 'run', '--config', cfgFile],
      env: { ...process.env, MCPHANTOM_HOME: home },
      stderr: 'pipe',
    });
    let stderr = '';
    transport.stderr?.on('data', (d: Buffer) => (stderr += d.toString()));
    await client.connect(transport);
    try {
      const tools = await client.listTools();
      expect(tools.tools.map((t) => t.name)).toContain('fx__echo');
      expect(textOf(await client.callTool({ name: 'fx__echo', arguments: { text: 'through the phantom' } }))).toBe('through the phantom');
      expect(textOf(await client.callTool({ name: 'fx__env', arguments: {} }))).toBe('secret=e2e-secret-value-42');
    } finally {
      await client.close();
    }
    await new Promise((r) => setTimeout(r, 500));
    expect(stderr).toContain("connected to 'fx'");
    expect(checkPrivate(cfgFile).ok).toBe(true); // the config was tightened to owner-only
    const db = path.join(home, 'data', 'events.db');
    expect(checkPrivate(db).ok).toBe(true);
    expect(checkPrivate(path.join(home, 'data')).ok).toBe(true);
    const bytes = Buffer.concat(['', '-wal'].filter((s) => fs.existsSync(db + s)).map((s) => fs.readFileSync(db + s)));
    expect(bytes.includes(Buffer.from('e2e-secret-value-42'))).toBe(false);
    expect(bytes.includes(Buffer.from('through the phantom'))).toBe(true); // non-secret payloads are logged
  });

  it('doctor reports paths and validates a config', () => {
    const r = runCli(['doctor', '--config', path.join(home, 'gw.yaml')]);
    expect(r.stdout).toContain('config dir');
    expect(r.stdout).toMatch(/valid, 1 server/);
  });
});
