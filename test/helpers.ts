import fs from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { ClientCapabilities } from '@modelcontextprotocol/sdk/types.js';
import { ConfigSchema, type Config } from '../src/config/schema.js';
import { Gateway } from '../src/gateway/gateway.js';
import type { RugpullChecker } from '../src/rugpull/checker.js';
import { SqliteStore } from '../src/store/store.js';
import { silentLogger } from '../src/util/log.js';
import type { TimingSink } from '../src/util/timings.js';
import { buildEverythingServer } from './fixtures/servers/everything-lib.js';

const here = path.dirname(fileURLToPath(import.meta.url));
export const ROOT = path.resolve(here, '..');
const require = createRequire(import.meta.url);
export const TSX_LOADER = pathToFileURL(require.resolve('tsx')).href;

export function fixture(name: string): string {
  return path.join(here, 'fixtures', 'servers', `${name}.ts`);
}

/** stdio server config that runs a TypeScript fixture through tsx. */
export function fixtureServer(name: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { command: process.execPath, args: ['--import', TSX_LOADER, fixture(name)], ...extra };
}

export function tempDir(prefix = 'mcphantom-test-'): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

export function makeConfig(raw: Record<string, unknown>): Config {
  return ConfigSchema.parse({ version: 1, ...raw });
}

export interface GatewayHarness {
  client: Client;
  gateway: Gateway;
  store: SqliteStore;
  dataDir: string;
  close(): Promise<void>;
}

export async function startGateway(
  servers: Record<string, Record<string, unknown>>,
  opts: { config?: Record<string, unknown>; clientCapabilities?: ClientCapabilities; knownSecrets?: string[]; setupClient?: (c: Client) => void; rugpull?: RugpullChecker; timings?: TimingSink } = {},
): Promise<GatewayHarness> {
  const config = makeConfig({ servers, ...opts.config });
  const dataDir = tempDir();
  const store = new SqliteStore({
    dataDir,
    payloads: config.logging.payloads,
    maxPayloadBytes: config.logging.max_payload_bytes,
    retentionDays: config.retention.days,
    retentionMaxMb: config.retention.max_mb,
    knownSecrets: opts.knownSecrets ?? [],
    redactEntropy: config.secrets.entropy.redact,
    insecurePermissions: 'fix',
    logger: silentLogger,
  });
  const sessionId = 'test-session';
  store.startSession({ id: sessionId });
  const gateway = await Gateway.create({ config, store, logger: silentLogger, sessionId, version: '0.0.0-test', ...(opts.rugpull ? { rugpull: opts.rugpull } : {}), ...(opts.timings ? { timings: opts.timings } : {}) });
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await gateway.connect(serverSide);
  const client = new Client({ name: 'test-client', version: '1.0.0' }, { capabilities: opts.clientCapabilities ?? {} });
  opts.setupClient?.(client);
  await client.connect(clientSide);
  return {
    client,
    gateway,
    store,
    dataDir,
    async close() {
      await client.close().catch(() => {});
      await gateway.close();
      store.close();
      fs.rmSync(dataDir, { recursive: true, force: true });
    },
  };
}

/** Direct connection to a fixture, bypassing MCPhantom (the conformance baseline). */
export async function connectDirect(name: string, capabilities: ClientCapabilities = {}): Promise<Client> {
  const client = new Client({ name: 'test-direct', version: '1.0.0' }, { capabilities });
  await client.connect(new StdioClientTransport({ command: process.execPath, args: ['--import', TSX_LOADER, fixture(name)], stderr: 'ignore' }));
  return client;
}

/**
 * In-process Streamable HTTP fixture (stateless). `requiredAuth` makes it reject requests without
 * that exact Authorization header, to prove headers are forwarded.
 */
export async function startHttpFixture(requiredAuth?: string): Promise<{ url: string; close(): Promise<void> }> {
  const srv = http.createServer((req, res) => {
    if (requiredAuth && req.headers.authorization !== requiredAuth) {
      res.writeHead(401).end('unauthorized');
      return;
    }
    const mcp = buildEverythingServer();
    const transport = new StreamableHTTPServerTransport({ enableJsonResponse: true }) // no sessionIdGenerator: stateless;
    res.on('close', () => {
      void transport.close();
      void mcp.close();
    });
    void mcp.connect(transport as unknown as Parameters<typeof mcp.connect>[0]).then(() => transport.handleRequest(req, res));
  });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  const { port } = srv.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/mcp`,
    close: () => new Promise((r) => { srv.closeAllConnections(); srv.close(() => { r(); }); }),
  };
}

export function textOf(result: unknown): string {
  const r = result as { content?: { type: string; text?: string }[] };
  return (r.content ?? []).map((c) => (c.type === 'text' ? c.text : `[${c.type}]`)).join('');
}
