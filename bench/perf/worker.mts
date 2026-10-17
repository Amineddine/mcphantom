/**
 * One launch of `bench:perf` (pre-registered in bench/perf/PREREGISTRATION-perf.md). The launcher
 * (`bench/perf-bench.mts`) starts each launch as a fresh process and reads the single JSON line it prints.
 *
 *   node --import tsx bench/perf/worker.mts '<job json>'
 *
 * Parts: `latency` (direct vs the built CLI), `breakdown` (CLI vs the bench entry with the timing hook off
 * and on, plus per-stage timings), `decision` (in process, the bench:policy configuration), `memory` (a long
 * session through the bench entry). Arms are interleaved in blocks; the first arm rotates with the launch.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { performance } from 'node:perf_hooks';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { stringify } from 'yaml';
import { prose } from './filler.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const TSX = pathToFileURL(createRequire(import.meta.url).resolve('tsx')).href;
const FIXTURE = path.join(ROOT, 'test', 'fixtures', 'servers', 'everything.ts');
const CLI = path.join(ROOT, 'dist', 'cli', 'main.js');
const ENTRY = path.join(ROOT, 'bench', 'perf', 'timed-gateway.mts');
const FS_SERVER = path.join(ROOT, 'node_modules', '@modelcontextprotocol', 'server-filesystem', 'dist', 'index.js');

export const SIZES = {
  '1k': { label: '1 KiB', text: () => 'x'.repeat(1024), warm: 20, n: 200 },
  '64k': { label: '64 KiB', text: () => 'x'.repeat(65_536), warm: 20, n: 100 },
  '1m': { label: '1 MiB', text: () => 'x'.repeat(1_048_576), warm: 5, n: 20 },
  slash128k: { label: '128 KiB slash-heavy (R6b-10)', text: () => 'aBcdefghijklmnoP/'.repeat(7710), warm: 5, n: 40 },
} as const;
export type SizeId = keyof typeof SIZES;

export interface Job {
  part: 'latency' | 'breakdown' | 'decision' | 'memory';
  launch: number;
  smoke?: boolean;
  sizes?: SizeId[];
  /** latency: gateway arms by `logging.payloads`. */
  logging?: ('redacted' | 'none')[];
  /** latency: also the real-server arm (server-filesystem). */
  real?: boolean;
  /** memory: `taint.max_index_mb` budgets. */
  budgets?: number[];
}

const job = JSON.parse(process.argv[2] ?? '{}') as Job;
const smoke = job.smoke === true;
const counts = (warm: number, n: number) => (smoke ? { warm: Math.min(warm, 2), n: Math.min(n, 5) } : { warm, n });
const rotate = <T,>(xs: T[], k: number) => xs.map((_, i) => xs[(i + k) % xs.length] as T);
const home = fs.mkdtempSync(path.join(os.tmpdir(), 'mcphantom-perf-'));

// ---- processes ------------------------------------------------------------------------------------------
interface Conn { client: Client; tool: string; close(): Promise<void>; out?: string }

const fixtureCmd = { command: process.execPath, args: ['--import', TSX, FIXTURE] };

function writeConfig(name: string, servers: Record<string, unknown>, extra: Record<string, unknown> = {}): string {
  const file = path.join(home, `${name}.yaml`);
  fs.writeFileSync(file, stringify({ version: 1, servers, logging: { level: 'warn', ...((extra.logging as object | undefined) ?? {}) }, ...Object.fromEntries(Object.entries(extra).filter(([k]) => k !== 'logging')) }));
  return file;
}

type GatewayKind = 'cli' | 'entry-off' | 'entry-on' | 'entry-mem';
async function connect(kind: 'direct' | GatewayKind, opts: { name: string; servers?: Record<string, unknown>; extra?: Record<string, unknown>; tool?: string; direct?: { command: string; args: string[] } } ): Promise<Conn> {
  const client = new Client({ name: 'bench-perf', version: '1' });
  const env = { ...process.env, MCPHANTOM_HOME: home } as Record<string, string>;
  let params;
  let out: string | undefined;
  if (kind === 'direct') {
    params = { ...(opts.direct ?? fixtureCmd), stderr: 'ignore' as const };
  } else {
    const cfg = writeConfig(opts.name, opts.servers ?? { fx: fixtureCmd }, opts.extra);
    if (kind === 'cli') params = { command: process.execPath, args: [CLI, 'run', '--config', cfg], env, stderr: 'ignore' as const };
    else {
      out = path.join(home, `${opts.name}.out.json`);
      const perf = kind === 'entry-on' ? { timings: true, out } : kind === 'entry-mem' ? { memEvery: 100, out } : { out };
      params = { command: process.execPath, args: ['--import', TSX, ENTRY, cfg], env: { ...env, MCPHANTOM_PERF: JSON.stringify(perf) }, stderr: 'ignore' as const };
    }
  }
  await client.connect(new StdioClientTransport(params));
  return { client, tool: opts.tool ?? (kind === 'direct' ? 'echo' : 'fx__echo'), close: () => client.close(), ...(out ? { out } : {}) };
}

/** Waits for a bench-entry process to write its records on exit. */
async function records(c: Conn): Promise<{ calls: Record<string, [number, number]>[]; memory: unknown[] }> {
  await c.close();
  for (let i = 0; i < 200 && c.out && !fs.existsSync(c.out); i++) await new Promise((r) => setTimeout(r, 50));
  if (!c.out || !fs.existsSync(c.out)) throw new Error(`no records from ${c.out ?? '?'}`);
  return JSON.parse(fs.readFileSync(c.out, 'utf8')) as { calls: Record<string, [number, number]>[]; memory: unknown[] };
}

async function measure(c: Conn, args: Record<string, unknown>, warm: number, n: number): Promise<number[]> {
  const out: number[] = [];
  for (let i = 0; i < warm + n; i++) {
    const t0 = performance.now();
    const r = await c.client.callTool({ name: c.tool, arguments: args });
    const dt = performance.now() - t0;
    if (r.isError) throw new Error(`call failed: ${JSON.stringify(r.content).slice(0, 200)}`);
    if (i >= warm) out.push(round(dt));
  }
  return out;
}
const round = (x: number) => Math.round(x * 1e4) / 1e4;

// ---- parts ----------------------------------------------------------------------------------------------
async function latency(): Promise<unknown> {
  const sizes = job.sizes ?? (Object.keys(SIZES) as SizeId[]);
  const logging = job.logging ?? ['redacted', 'none'];
  const conns = new Map<string, Conn>();
  conns.set('direct', await connect('direct', { name: 'direct' }));
  for (const p of logging) conns.set(`gateway/${p}`, await connect('cli', { name: `gw-${p}`, extra: { logging: { payloads: p } } }));
  const order = rotate([...conns.keys()], job.launch);
  const samples: Record<string, Record<string, number[]>> = {};
  try {
    for (const s of sizes) {
      const { warm, n } = counts(SIZES[s].warm, SIZES[s].n);
      const args = { text: SIZES[s].text() };
      samples[s] = {};
      for (const arm of order) samples[s][arm] = await measure(conns.get(arm) as Conn, args, warm, n);
    }
    if (job.real) {
      const dir = fs.mkdtempSync(path.join(home, 'fs-'));
      const file = path.join(dir, 'page.txt');
      fs.writeFileSync(file, prose(65_536, 7));
      const fsCmd = { command: process.execPath, args: [FS_SERVER, dir] };
      const real = new Map<string, Conn>([
        ['direct', await connect('direct', { name: 'fs-direct', direct: fsCmd, tool: 'read_text_file' })],
        ['gateway/redacted', await connect('cli', { name: 'fs-gw', servers: { fs: fsCmd }, tool: 'fs__read_text_file' })],
      ]);
      const { warm, n } = counts(20, 100);
      samples.real64k = {};
      for (const arm of rotate([...real.keys()], job.launch)) samples.real64k[arm] = await measure(real.get(arm) as Conn, { path: file }, warm, n);
      for (const c of real.values()) await c.close();
    }
  } finally {
    for (const c of conns.values()) await c.close().catch(() => {});
  }
  return { samples };
}

/** Per-call stage durations (ms) from the bench entry's marks; see the stage table in the pre-registration. */
function derive(m: Record<string, [number, number]>): Record<string, number> {
  const dur = (k: string) => { const v = m[k]; return v ? v[1] - v[0] : NaN; };
  const at = (k: string, i: 0 | 1) => m[k]?.[i] ?? NaN;
  const d: Record<string, number> = {
    'down.parse': dur('down.parse'),
    'down.validate': at('handler', 0) - at('down.parse', 1),
    resolve: dur('resolve'), decide: dur('decide'), 'audit.decision': dur('audit.decision'), sent: dur('sent'),
    'up.send': dur('up.send'),
    'up.wait': at('up.parse', 0) - at('up.send', 1),
    'up.parse': dur('up.parse'),
    'up.validate': at('upstream', 1) - at('up.parse', 1),
    ingest: dur('ingest'), 'audit.ingest': dur('audit.ingest'), 'audit.request': dur('audit.request'),
    'down.respond': at('down.send', 0) - at('handler', 1),
    'down.send': dur('down.send'), 'down.drain': dur('down.send.drain'),
    redact: dur('redact'), 'store.write': dur('store.write'),
    inside: at('down.send.drain', 1) - at('down.parse', 0),
  };
  return Object.fromEntries(Object.entries(d).map(([k, v]) => [k, Number.isNaN(v) ? 0 : round(v)]));
}

async function breakdown(): Promise<unknown> {
  const sizes = job.sizes ?? (['1k', '1m', 'slash128k'] as SizeId[]);
  const kinds: GatewayKind[] = ['cli', 'entry-off', 'entry-on'];
  const conns = new Map<GatewayKind, Conn>();
  for (const k of kinds) conns.set(k, await connect(k, { name: k }));
  const order = rotate(kinds, job.launch);
  const samples: Record<string, Record<string, number[]>> = {};
  const plan: { size: SizeId; warm: number; n: number }[] = [];
  try {
    for (const s of sizes) {
      const { warm, n } = counts(SIZES[s].warm, SIZES[s].n);
      plan.push({ size: s, warm, n });
      const args = { text: SIZES[s].text() };
      samples[s] = {};
      for (const k of order) samples[s][k] = await measure(conns.get(k) as Conn, args, warm, n);
    }
  } finally {
    for (const [k, c] of conns) if (k !== 'entry-on') await c.close().catch(() => {});
  }
  // The timed process served, in order, warmup + measured calls per size.
  const recs = (await records(conns.get('entry-on') as Conn)).calls;
  const expected = plan.reduce((a, p) => a + p.warm + p.n, 0);
  if (recs.length !== expected) throw new Error(`breakdown: ${recs.length} timed calls, expected ${expected}`);
  const stages: Record<string, Record<string, number>[]> = {};
  let i = 0;
  for (const p of plan) {
    i += p.warm;
    stages[p.size] = recs.slice(i, i + p.n).map(derive);
    i += p.n;
  }
  return { samples, stages };
}

async function decision(): Promise<unknown> {
  const { ConfigSchema } = await import('../../src/config/schema.js');
  const { PolicyEngine } = await import('../../src/policy/engine.js');
  const { TaintEngine } = await import('../../src/taint/engine.js');
  const config = ConfigSchema.parse({
    version: 1,
    servers: {
      mail: { command: 'x', tools: { send: { effect: 'egress', integrity: 'trusted', rules: [
        { deny: 'containsSecret(arg.body)' },
        { deny: 'glob(arg.path, ["**/.env*", "**/.ssh/**", "**/*credentials*"])' },
        { deny: 'from(arg.to, "untrusted")' },
        { ask: 'context.integrity == "untrusted"' },
        { allow: 'within(arg.path, "./workspace")' },
      ] } } },
      // Filler source for the full-index case: trusted and public, so the context label does not change.
      docs: { command: 'x', tools: { read: { effect: 'read', integrity: 'trusted', confidentiality: 'public' } } },
    },
  });
  const base = { to: 'me@corp.example', path: 'workspace/x' };
  const proseBody = prose(64, 11);
  const cases: { id: string; args: Record<string, unknown>; n: number; fill?: boolean }[] = [
    { id: 'small', args: { ...base, body: 'hello' }, n: 2000 },
    { id: 'body128k', args: { ...base, body: 'a '.repeat(64 * 1024) }, n: 100 },
    { id: 'slash128k', args: { ...base, body: 'aBcdefghijklmnoP/'.repeat(7710) }, n: 100 },
    { id: 'body1m', args: { ...base, body: 'a'.repeat(1_048_576) }, n: 50 },
    { id: 'prose64-empty', args: { ...base, body: proseBody }, n: 500 },
    { id: 'prose64-full', args: { ...base, body: proseBody }, n: 200, fill: true },
    // Amendment 2: an 8 KiB argument against a full index (found while building M2; see the pre-registration).
    { id: 'prose8k-full', args: { ...base, body: prose(8192, 12) }, n: 20, fill: true },
  ];
  const out: Record<string, { samples: number[]; deadline: number; n: number; fill?: unknown }> = {};
  for (const c of rotate(cases, job.launch)) {
    const engine = new TaintEngine(config, new PolicyEngine(config));
    let fill: unknown;
    if (c.fill) {
      const pages = Array.from({ length: 50 }, (_, i) => prose(8192, 100 + i));
      let k = 0;
      while (engine.indexStats.evicted === 0) engine.ingest('tool', 'docs', 'docs__read', 'read', { content: [{ type: 'text', text: pages[k++ % pages.length] }] });
      fill = { outputs: k, ...engine.indexStats };
    }
    const n = smoke ? Math.min(c.n, 5) : c.n;
    const samples: number[] = [];
    let deadline = 0;
    for (let i = 0; i < n; i++) {
      const t0 = performance.now();
      const d = engine.decide('mail', 'send', 'mail__send', c.args);
      samples.push(round(performance.now() - t0));
      if (d.policy?.errors.some((e) => e.message.includes('time budget'))) deadline++;
    }
    out[c.id] = { samples, deadline, n, ...(fill ? { fill } : {}) };
  }
  return { cases: out };
}

/** Amendment 1 (pre-registration): the long session reads 8 KiB files through server-filesystem instead of
 *  echoing 8 KiB arguments — an 8 KiB argument is attributed against all of Tier A on every call. */
async function memory(): Promise<unknown> {
  const budgets = job.budgets ?? [32, 4];
  const calls = smoke ? 400 : 4000;
  const dir = fs.mkdtempSync(path.join(home, 'pages-'));
  const files = Array.from({ length: 50 }, (_, i) => {
    const f = path.join(dir, `p${i}.txt`);
    fs.writeFileSync(f, prose(8192, 1000 + i));
    return f;
  });
  const fsCmd = { command: process.execPath, args: [FS_SERVER, dir] };
  const series: Record<string, unknown[]> = {};
  for (const b of rotate(budgets, job.launch)) {
    const c = await connect('entry-mem', { name: `mem-${String(b)}`, servers: { fs: fsCmd }, tool: 'fs__read_text_file', extra: { taint: { max_index_mb: b } } });
    for (let i = 0; i < calls; i++) await c.client.callTool({ name: c.tool, arguments: { path: files[i % files.length] } });
    series[String(b)] = (await records(c)).memory;
  }
  return { series };
}

try {
  const parts = { latency, breakdown, decision, memory };
  const result = await parts[job.part]();
  process.stdout.write(`${JSON.stringify({ job, result })}\n`);
} finally {
  fs.rmSync(home, { recursive: true, force: true });
}
