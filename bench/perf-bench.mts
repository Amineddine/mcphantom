/**
 * Phase 7 item 5 — latency, memory, eviction loss (pre-registered in bench/perf/PREREGISTRATION-perf.md).
 *
 *   npm run build && npm run bench:perf -- --env ci --replicate 1          # the full matrix (CI)
 *   npm run build && npm run bench:perf -- --env laptop --set reduced      # the owner's reduced laptop set
 *   npm run bench:perf -- --parts eviction [--shard 3/8]                   # E + M1 only (deterministic)
 *   options: --parts latency,breakdown,decision,memory,eviction  --launches 10  --smoke
 *
 * Latency, breakdown, decision and memory run as independent launches: each launch is a fresh process
 * (`bench/perf/worker.mts`), started one after another. Eviction and per-trace memory are deterministic and
 * run once, in process. Raw results go to `bench/results/perf/<env>-<replicate>.json` (`--smoke` writes to
 * the system temp directory and is never reported); `bench/perf/report.mts` builds the report from them.
 */
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { parseArgs } from 'node:util';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { loadScenario } from './attack/scenario.js';
import { runAll } from './perf/eviction.js';
import type { Job } from './perf/worker.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(here, '..');
const TSX = pathToFileURL(createRequire(import.meta.url).resolve('tsx')).href;
const { values: v } = parseArgs({
  options: {
    env: { type: 'string', default: 'laptop' }, replicate: { type: 'string', default: '1' }, set: { type: 'string', default: 'full' },
    parts: { type: 'string' }, shard: { type: 'string' }, launches: { type: 'string', default: '10' }, smoke: { type: 'boolean', default: false },
  },
});
const reduced = v.set === 'reduced';
// Eviction is deterministic and runs on its own, in shards (amendment 3), so it is never in the default list.
const parts = (v.parts ?? (reduced ? 'latency,breakdown' : 'latency,breakdown,decision,memory')).split(',');
const launches = v.smoke ? 1 : Number(v.launches);
if (!v.smoke && launches < 10) throw new Error('pre-registered: ≥ 10 launches per configuration');
if (!fs.existsSync(path.join(ROOT, 'dist', 'cli', 'main.js'))) throw new Error('dist/ not found: run `npm run build` first');

function sh(cmd: string, args: string[]): string {
  try {
    return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 20_000 }).trim();
  } catch {
    return 'unknown';
  }
}
/** Windows laptop: AC power and the active power plan. Elsewhere: not applicable. */
function power(): string {
  if (process.platform !== 'win32') return 'n/a';
  const ac = sh('powershell', ['-NoProfile', '-Command', '(Get-CimInstance -ClassName BatteryStatus -Namespace root/wmi -ErrorAction SilentlyContinue | Select-Object -First 1).PowerOnline']);
  const plan = sh('powercfg', ['/getactivescheme']);
  return `on AC: ${ac === 'True' ? 'yes' : ac === 'False' ? 'NO' : ac}; ${plan}`;
}
const env = {
  env: v.env, replicate: Number(v.replicate), set: v.set, smoke: v.smoke, date: new Date().toISOString(),
  commit: sh('git', ['rev-parse', 'HEAD']), node: process.version, os: `${os.type()} ${os.release()} ${os.arch()}`,
  cpu: os.cpus()[0]?.model ?? 'unknown', cores: os.cpus().length, memGb: Math.round(os.totalmem() / 2 ** 30), power: power(),
  runner: process.env.RUNNER_NAME ? `${process.env.RUNNER_NAME} (${process.env.RUNNER_ENVIRONMENT ?? '?'}, image ${process.env.ImageOS ?? '?'} ${process.env.ImageVersion ?? ''})`.trim() : 'local',
  launches,
};

function launch(job: Job): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const p = spawn(process.execPath, ['--import', TSX, path.join(here, 'perf', 'worker.mts'), JSON.stringify(job)], { stdio: ['ignore', 'pipe', 'inherit'] });
    let out = '';
    p.stdout.on('data', (d: Buffer) => (out += d.toString('utf8')));
    p.on('error', reject);
    p.on('exit', (code) => {
      if (code !== 0) {
        reject(new Error(`launch ${job.part}#${job.launch} exited ${String(code)}`));
        return;
      }
      const line = out.trim().split('\n').pop() ?? '';
      try {
        resolve((JSON.parse(line) as { result: unknown }).result);
      } catch {
        reject(new Error(`launch ${job.part}#${job.launch}: no result`));
      }
    });
  });
}

const results: Record<string, unknown> = {};
const jobFor = (part: Job['part'], i: number): Job => {
  const base = { part, launch: i, smoke: v.smoke };
  if (part === 'latency') return reduced ? { ...base, sizes: ['1m', 'slash128k'], logging: ['redacted'] } : { ...base, real: v.env === 'ci' };
  if (part === 'breakdown') return reduced ? { ...base, sizes: ['1m', 'slash128k'] } : base;
  return base;
};
for (const part of parts.filter((p) => p !== 'eviction') as Job['part'][]) {
  const runs: unknown[] = [];
  for (let i = 0; i < launches; i++) {
    const t0 = Date.now();
    runs.push(await launch(jobFor(part, i)));
    process.stderr.write(`${part}: launch ${i + 1}/${launches} (${((Date.now() - t0) / 1000).toFixed(1)} s)\n`);
  }
  results[part] = runs;
}
if (parts.includes('eviction')) {
  const load = (f: string) => (JSON.parse(fs.readFileSync(path.join(here, 'attack', f), 'utf8')) as unknown[]).map(loadScenario);
  const sets = [
    { id: 'suite', title: 'Item-3 suite (83 traces, unchanged)', scenarios: load('scenarios.json') },
    { id: 'policy', title: 'Policy family (8 traces, unchanged)', scenarios: load('scenarios-policy.json') },
  ];
  const t0 = Date.now();
  const shard = v.shard ? (v.shard.split('/').map(Number) as [number, number]) : undefined;
  results.eviction = runAll(sets, { smoke: v.smoke, ...(shard ? { shard: [shard[0] - 1, shard[1]] as [number, number] } : {}) });
  results.shard = v.shard ?? '1/1';
  process.stderr.write(`eviction: done (${((Date.now() - t0) / 1000).toFixed(1)} s)\n`);
}

const outDir = v.smoke ? fs.mkdtempSync(path.join(os.tmpdir(), 'mcphantom-perf-smoke-')) : path.join(ROOT, 'bench', 'results', 'perf');
fs.mkdirSync(outDir, { recursive: true });
const out = path.join(outDir, `${v.env}-${v.replicate}${parts.length === 1 ? `-${parts[0] ?? ''}` : ''}${v.shard ? `-${v.shard.replace('/', 'of')}` : ''}.json`);
fs.writeFileSync(out, `${JSON.stringify({ env, results })}\n`);
process.stderr.write(`wrote ${out}\n`);
