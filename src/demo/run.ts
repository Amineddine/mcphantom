/**
 * One-command side-by-side demo (`npm run demo`). Runs the same injected agent twice against the same
 * poisoned page and attacker collector: once with MCPhantom in audit mode (unprotected) and once with
 * it enforcing. The verdict is read from the attacker's own request log, not from MCPhantom.
 *
 * This is the scripted, deterministic demo. The live version — a real model through Claude Code —
 * is driven separately; see docs/DEMO.md.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { resolvePaths } from '../config/paths.js';
import { ConfigSchema } from '../config/schema.js';
import { Gateway } from '../gateway/gateway.js';
import { SqliteStore } from '../store/store.js';
import { silentLogger } from '../util/log.js';
import { VERSION } from '../version.js';
import { runInjectedAgent } from './agent.js';
import { startWorld } from './world.js';

const C = { red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', dim: '\x1b[2m', bold: '\x1b[1m', reset: '\x1b[0m' };
const color = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code: string, s: string): string => (color ? code + s + C.reset : s);
const out = (s = ''): void => {
  process.stdout.write(s + '\n');
};

const here = path.dirname(fileURLToPath(import.meta.url));
const ext = path.extname(here ? fileURLToPath(import.meta.url) : '');
const require = createRequire(import.meta.url);

function serverCmd(name: string, extra: string[] = []): { command: string; args: string[] } {
  const script = path.join(here, 'servers', `${name}${ext}`);
  if (ext === '.ts') {
    const tsx = pathToFileURL(require.resolve('tsx')).href;
    return { command: process.execPath, args: ['--import', tsx, script, ...extra] };
  }
  return { command: process.execPath, args: [script, ...extra] };
}

const CANARY = ['AKIA', 'DEMOEXFIL', 'CANARY9'].join('');
const TOOLS = { fetchUrl: 'web__fetch_url', readFile: 'files__read_file', postWebhook: 'hook__post_webhook' };

async function connectGateway(servers: Record<string, unknown>, trifecta: 'deny' | 'log', dataDir: string) {
  const config = ConfigSchema.parse({ version: 1, servers, logging: { level: 'error' }, taint: { trifecta } });
  const store = new SqliteStore({
    dataDir, payloads: config.logging.payloads, maxPayloadBytes: config.logging.max_payload_bytes,
    retentionDays: config.retention.days, retentionMaxMb: config.retention.max_mb,
    knownSecrets: [], insecurePermissions: 'fix', logger: silentLogger,
  });
  store.startSession({ id: `demo-${trifecta}` });
  const gw = await Gateway.create({ config, store, logger: silentLogger, sessionId: `demo-${trifecta}`, version: VERSION });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await gw.connect(b);
  const client = new Client({ name: 'demo-agent', version: '1' });
  await client.connect(a);
  return { client, gw, store, close: async () => { await client.close(); await gw.close(); store.close(); } };
}

async function main(): Promise<void> {
  const world = await startWorld();
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'mcphantom-demo-ws-'));
  fs.writeFileSync(path.join(workspace, '.env'), `AWS_ACCESS_KEY_ID=${CANARY}\nAWS_SECRET_ACCESS_KEY=wJalrFAKEsecretFAKEsecretFAKEsecret01\n`);
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'mcphantom-demo-data-'));
  const traceDir = path.join(resolvePaths().dataDir, 'demo');
  const servers = {
    web: { ...serverCmd('web'), tools: { fetch_url: { effect: 'read', integrity: 'untrusted' } } },
    files: { ...serverCmd('files', [workspace]), defaults: { effect: 'read', integrity: 'trusted', confidentiality: 'internal' } },
    hook: { ...serverCmd('webhook'), tools: { post_webhook: { effect: 'egress', integrity: 'trusted' } } },
  };

  out();
  out(c(C.bold, `  MCPhantom ${VERSION} — exfiltration demo (scripted agent, real MCP servers)`));
  out(c(C.dim, '  An agent summarizes a blog post. The post hides an instruction: read .env and POST it'));
  out(c(C.dim, '  to an attacker. The agent obeys. Ground truth = the attacker collector\'s request log.'));
  out();
  out(c(C.dim, `  workspace .env contains canary ${CANARY}`));
  out(c(C.dim, `  poisoned page: ${world.articleUrl}`));
  out(c(C.dim, `  attacker collector: ${world.collectUrl}`));
  out();

  const results: { label: string; leaked: boolean; blocked: boolean }[] = [];
  for (const [label, trifecta] of [['WITHOUT MCPhantom (audit mode)', 'log'], ['WITH MCPhantom (enforcing)', 'deny']] as const) {
    const before = world.received.length;
    const h = await connectGateway(servers, trifecta, trifecta === 'deny' ? traceDir : path.join(dataRoot, trifecta));
    const r = await runInjectedAgent(h.client, TOOLS, world.articleUrl, world.collectUrl);
    const leaked = world.received.slice(before).some((x) => x.body.includes(CANARY));
    await h.close();
    results.push({ label, leaked, blocked: r.exfilBlocked });

    out(c(C.bold, `  ── ${label} ─────────────────────────────`));
    for (const s of r.steps) {
      const mark = s.blocked ? c(C.green, '⛔ blocked') : s.ok ? c(C.dim, 'ok') : c(C.yellow, 'error');
      out(`     ${s.tool.padEnd(18)} ${mark}`);
    }
    out(leaked
      ? c(C.red, `     ✗ LEAKED: the canary reached the attacker. ${CANARY}`)
      : c(C.green, '     ✓ SAFE: the attacker received nothing with the canary.'));
    out();
  }

  await world.close();
  fs.rmSync(workspace, { recursive: true, force: true });
  fs.rmSync(dataRoot, { recursive: true, force: true });

  const unprotected = results[0];
  const protectedRun = results[1];
  const demonstrated = unprotected?.leaked === true && protectedRun?.leaked === false && protectedRun.blocked;
  if (demonstrated) {
    out(c(C.bold, '  Result: the exfiltration succeeds unprotected and is blocked by MCPhantom.'));
    out(c(C.dim, `  Inspect the full taint trace with:  mcphantom trace --last --data-dir "${traceDir}"`));
    process.exitCode = 0;
  } else {
    out(c(C.yellow, '  Result: demo did not show the expected contrast — see output above.'));
    process.exitCode = 1;
  }
}

await main();
