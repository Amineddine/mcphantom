/**
 * Bench-only gateway entry for `bench:perf` (Phase 7 item 5; pre-registered in
 * bench/perf/PREREGISTRATION-perf.md). It builds the gateway from the built `dist/` the way `mcphantom run`
 * does (config file, SQLite store, stdio), and can switch on the internal timing hook, which the CLI never
 * passes:
 *
 *   node --import tsx bench/perf/timed-gateway.mts <config.yaml>
 *   MCPHANTOM_PERF='{"timings":true,"memEvery":100,"out":"<file.json>"}'
 *
 * With `timings`, it also wraps SDK prototypes **in this process only** (the stdio read buffer and both
 * stdio transports' `send`), so the transport stages of a `tools/call` are timestamped too. Records are
 * kept in memory and written to `out` when the client disconnects, so recording adds no I/O to the call path.
 * No lockfile (rug-pull pins are not part of the timed path).
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ReadBuffer } from '@modelcontextprotocol/sdk/shared/stdio.js';
import type { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js';
import type { TimingStage } from '../../src/util/timings.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const dist = async <T,>(p: string): Promise<T> => (await import(pathToFileURL(path.join(ROOT, 'dist', p)).href)) as T;
const { Gateway } = await dist<typeof import('../../src/gateway/gateway.js')>('gateway/gateway.js');
const { SqliteStore } = await dist<typeof import('../../src/store/store.js')>('store/store.js');
const { loadConfigFile } = await dist<typeof import('../../src/config/load.js')>('config/load.js');
const { createLogger } = await dist<typeof import('../../src/util/log.js')>('util/log.js');
const { VERSION } = await dist<typeof import('../../src/version.js')>('version.js');
const { resolvePaths } = await dist<typeof import('../../src/config/paths.js')>('config/paths.js');

interface Opts { timings?: boolean; memEvery?: number; out?: string }
const opts = JSON.parse(process.env.MCPHANTOM_PERF ?? '{}') as Opts;
const file = process.argv[2];
if (!file) throw new Error('usage: timed-gateway.mts <config.yaml>');

/** Stage marks of one `tools/call`, `[start, end]` in `performance.now()` ms. */
type Marks = Record<string, [number, number]>;
const calls: Marks[] = [];
const memory: { calls: number; rss: number; heapUsed: number; tierABytes: number; tierAOutputs: number; tierBEntries: number; evicted: number }[] = [];
let cur: Marks = {};
let served = 0;
// The store emits redact/store.write once per event, several per call: summed per call.
const add = (k: string, s: number, e: number) => {
  const prev = cur[k];
  cur[k] = prev ? [prev[0], prev[1] + (e - s)] : [s, e];
};
const sumKeys = new Set(['redact', 'store.write']);

const isCall = (m: JSONRPCMessage) => 'method' in m && m.method === 'tools/call';
const isCallResult = (m: JSONRPCMessage) => 'result' in m && Array.isArray((m.result as { content?: unknown }).content);

if (opts.timings) {
  // Both directions parse through the same ReadBuffer class: the request from the client and the
  // response from the upstream server.
  // eslint-disable-next-line @typescript-eslint/unbound-method -- re-bound with .call below
  const read = ReadBuffer.prototype.readMessage;
  ReadBuffer.prototype.readMessage = function (this: ReadBuffer) {
    const t0 = performance.now();
    const msg = read.call(this);
    const t1 = performance.now();
    if (msg && isCall(msg)) {
      cur = {};
      cur['down.parse'] = [t0, t1];
    } else if (msg && isCallResult(msg)) cur['up.parse'] = [t0, t1];
    return msg;
  };
  type Sender = { send(m: JSONRPCMessage): Promise<void> };
  const wrapSend = (proto: Sender, stage: string, match: (m: JSONRPCMessage) => boolean) => {
    // eslint-disable-next-line @typescript-eslint/unbound-method -- re-bound with .call below
    const send = proto.send;
    proto.send = function (this: Sender, m: JSONRPCMessage) {
      if (!match(m)) return send.call(this, m);
      const t0 = performance.now();
      const p = send.call(this, m);
      const t1 = performance.now();
      cur[stage] = [t0, t1];
      return p.then(() => {
        cur[`${stage}.drain`] = [t1, performance.now()];
        if (stage === 'down.send') calls.push(cur);
      });
    };
  };
  wrapSend(StdioServerTransport.prototype, 'down.send', isCallResult);
  wrapSend(StdioClientTransport.prototype, 'up.send', isCall);
}

let gateway: Awaited<ReturnType<typeof Gateway.create>> | undefined = undefined;
const sink = (stage: TimingStage, start: number, end: number): void => {
  if (opts.timings) {
    if (sumKeys.has(stage)) add(stage, start, end);
    else cur[stage] = [start, end];
  }
  if (stage === 'handler') {
    served++;
    if (opts.memEvery && served % opts.memEvery === 0 && gateway) {
      const m = process.memoryUsage();
      memory.push({ calls: served, rss: m.rss, heapUsed: m.heapUsed, ...gateway.taint.indexStats });
    }
  }
};
const hooked = opts.timings === true || (opts.memEvery ?? 0) > 0;

const loaded = loadConfigFile(file);
const cfg = loaded.config;
const logger = createLogger(cfg.logging.level);
const store = new SqliteStore({
  dataDir: cfg.data_dir ? path.resolve(path.dirname(file), cfg.data_dir) : resolvePaths().dataDir,
  payloads: cfg.logging.payloads,
  maxPayloadBytes: cfg.logging.max_payload_bytes,
  retentionDays: cfg.retention.days,
  retentionMaxMb: cfg.retention.max_mb,
  knownSecrets: loaded.secrets,
  redactEntropy: cfg.secrets.entropy.redact,
  insecurePermissions: cfg.security.insecure_permissions,
  logger,
  ...(opts.timings ? { timings: sink } : {}),
});
const sessionId = crypto.randomUUID();
store.startSession({ id: sessionId });
gateway = await Gateway.create({ config: cfg, store, logger, sessionId, version: VERSION, ...(hooked ? { timings: sink } : {}) });

// Written as soon as the client disconnects: the SDK client terminates the process if shutdown (closing
// the upstream) takes longer than its grace period, and no exit handler runs then.
const writeOut = () => {
  if (opts.out) fs.writeFileSync(opts.out, JSON.stringify({ calls, memory }));
};
let finished = false;
const finish = async (): Promise<void> => {
  if (finished) return;
  finished = true;
  writeOut();
  await gateway.close();
  store.endSession(sessionId);
  store.close();
  process.exit(0);
};
void gateway.disconnected.then(finish);
// The stdio server transport does not watch for end of input; the client closing stdin is the disconnect.
process.stdin.once('end', () => void finish());
for (const sig of ['SIGINT', 'SIGTERM'] as const) process.once(sig, () => void finish());
await gateway.connect(new StdioServerTransport());
