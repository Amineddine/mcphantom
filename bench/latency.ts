/**
 * Phase-1 latency benchmark: round-trip time of tools/call, direct vs. through the MCPhantom gateway
 * (the real built CLI as a separate process, exactly as an MCP client would launch it).
 *
 *   npm run build && npm run bench:latency
 *
 * Method: same echo fixture server in both arms; sequential calls (no pipelining) after warmup;
 * per-size sample counts below; percentiles from the sorted samples. Both arms run in the same
 * process on the same machine, interleaved per size to spread out thermal/background noise.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { stringify } from 'yaml';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const TSX = pathToFileURL(createRequire(import.meta.url).resolve('tsx')).href;
const FIXTURE = path.join(ROOT, 'test', 'fixtures', 'servers', 'everything.ts');
const CLI = path.join(ROOT, 'dist', 'cli', 'main.js');

const SIZES = [
  { label: '1 KB', bytes: 1024, n: 2000 },
  { label: '64 KB', bytes: 65_536, n: 500 },
  { label: '1 MB', bytes: 1_048_576, n: 60 },
];
const WARMUP = 100;

interface Stats { n: number; p50: number; p95: number; p99: number; mean: number }

function stats(samples: number[]): Stats {
  const s = [...samples].sort((a, b) => a - b);
  const q = (p: number) => s[Math.min(s.length - 1, Math.floor(p * s.length))] ?? NaN;
  return { n: s.length, p50: q(0.5), p95: q(0.95), p99: q(0.99), mean: s.reduce((a, b) => a + b, 0) / s.length };
}

async function connect(viaGateway: boolean, home: string): Promise<Client> {
  const client = new Client({ name: 'bench', version: '1' });
  const fixtureCmd = { command: process.execPath, args: ['--import', TSX, FIXTURE] };
  let params;
  if (viaGateway) {
    const cfg = path.join(home, 'bench.yaml');
    fs.writeFileSync(cfg, stringify({ version: 1, servers: { fx: fixtureCmd }, logging: { level: 'warn' } }));
    params = { command: process.execPath, args: [CLI, 'run', '--config', cfg], env: { ...process.env, MCPHANTOM_HOME: home } as Record<string, string>, stderr: 'ignore' as const };
  } else {
    params = { ...fixtureCmd, stderr: 'ignore' as const };
  }
  await client.connect(new StdioClientTransport(params));
  return client;
}

async function measure(client: Client, tool: string, text: string, n: number): Promise<number[]> {
  const out: number[] = [];
  for (let i = 0; i < WARMUP + n; i++) {
    const t0 = performance.now();
    await client.callTool({ name: tool, arguments: { text } });
    const dt = performance.now() - t0;
    if (i >= WARMUP) out.push(dt);
  }
  return out;
}

async function main(): Promise<void> {
  if (!fs.existsSync(CLI)) throw new Error('dist/ not found: run `npm run build` first');
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'mcphantom-bench-'));
  const direct = await connect(false, home);
  const gw = await connect(true, home);
  const rows: { size: string; direct: Stats; gateway: Stats }[] = [];
  try {
    for (const size of SIZES) {
      const text = 'x'.repeat(size.bytes);
      const d = await measure(direct, 'echo', text, size.n);
      const g = await measure(gw, 'fx__echo', text, size.n);
      rows.push({ size: size.label, direct: stats(d), gateway: stats(g) });
      process.stderr.write(`${size.label}: done\n`);
    }
  } finally {
    await direct.close();
    await gw.close();
    fs.rmSync(home, { recursive: true, force: true });
  }

  const env = {
    date: new Date().toISOString(),
    node: process.version,
    os: `${os.type()} ${os.release()} ${os.arch()}`,
    cpu: os.cpus()[0]?.model ?? 'unknown',
    cores: os.cpus().length,
    memGb: Math.round(os.totalmem() / 2 ** 30),
    logging: 'payloads: redacted (default)',
  };
  const f = (x: number) => x.toFixed(2);
  const md = [
    `# Phase 1 latency: tools/call round trip, direct vs. via MCPhantom`,
    '',
    `Measured ${env.date} on ${env.cpu} (${env.cores} logical cores, ${env.memGb} GB), ${env.os}, Node ${env.node}.`,
    `Gateway = built CLI as a separate stdio process, default config (${env.logging}). Warmup ${WARMUP} calls, then sequential calls.`,
    '',
    '| payload | n | direct p50 | gateway p50 | Δ p50 | direct p95 | gateway p95 | Δ p95 | direct p99 | gateway p99 |',
    '|---|---|---|---|---|---|---|---|---|---|',
    ...rows.map((r) => `| ${r.size} | ${r.direct.n} | ${f(r.direct.p50)} ms | ${f(r.gateway.p50)} ms | +${f(r.gateway.p50 - r.direct.p50)} ms | ${f(r.direct.p95)} ms | ${f(r.gateway.p95)} ms | +${f(r.gateway.p95 - r.direct.p95)} ms | ${f(r.direct.p99)} ms | ${f(r.gateway.p99)} ms |`),
    '',
    'The gateway adds one extra stdio hop (JSON parse + serialize on each side), routing, and a synchronous',
    'SQLite write with redaction of up to 128 KiB of payload. No taint tracking or policy evaluation exists yet',
    '(Phase 2+); those costs will be measured separately.',
    '',
  ].join('\n');
  const outDir = path.join(ROOT, 'bench', 'results');
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, 'phase1-latency.json'), JSON.stringify({ env, rows }, null, 2) + '\n');
  fs.writeFileSync(path.join(outDir, 'phase1-latency.md'), md);
  process.stdout.write(md);
}

await main();
