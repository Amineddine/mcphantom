import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { getDefaultEnvironment, StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import {
  CreateMessageRequestSchema,
  ElicitRequestSchema,
  ErrorCode,
  ListRootsRequestSchema,
  LoggingMessageNotificationSchema,
  McpError,
  PromptListChangedNotificationSchema,
  ResourceListChangedNotificationSchema,
  ResourceUpdatedNotificationSchema,
  ToolListChangedNotificationSchema,
  type ClientCapabilities,
  type CreateMessageRequest,
  type CreateMessageResult,
  type ElicitRequest,
  type ElicitResult,
  type ListRootsResult,
  type LoggingMessageNotification,
  type Prompt,
  type Resource,
  type ResourceTemplate,
  type ResourceUpdatedNotification,
  type ServerCapabilities,
  type Tool,
} from '@modelcontextprotocol/sdk/types.js';
import type { ServerConfig } from '../config/schema.js';
import { errorMessage } from '../util/errors.js';
import type { Logger } from '../util/log.js';

export interface UpstreamHooks {
  onListChanged(serverId: string, kind: 'tools' | 'resources' | 'prompts'): void;
  onResourceUpdated(serverId: string, params: ResourceUpdatedNotification['params']): void;
  onLog(serverId: string, params: LoggingMessageNotification['params']): void;
  onClose(serverId: string, reason: string): void;
  /** Server→client requests, relayed to the downstream client. */
  listRoots(serverId: string): Promise<ListRootsResult>;
  elicit(serverId: string, params: ElicitRequest['params']): Promise<ElicitResult>;
  createMessage(serverId: string, params: CreateMessageRequest['params']): Promise<CreateMessageResult>;
  /** A request the upstream sent that MCPhantom refuses (unknown method, or sampling not allowed). */
  onRefusedRequest(serverId: string, method: string, reason: string): void;
}

export interface PaginationLimits {
  maxPages: number;
  maxItems: number;
  /** Total serialized size of all items, across pages. Each page is already ≤ 10 MB on the wire. */
  maxBytes: number;
}

export const DEFAULT_PAGINATION: PaginationLimits = { maxPages: 100, maxItems: 10_000, maxBytes: 32 * 1024 * 1024 };

export type UpstreamStatus = 'idle' | 'connecting' | 'ready' | 'failed' | 'closed';

/** One upstream MCP server and the SDK client MCPhantom uses to talk to it. */
export class Upstream {
  readonly id: string;
  readonly config: ServerConfig;
  readonly client: Client;
  status: UpstreamStatus = 'idle';
  failure: string | undefined;
  private transport: Transport | undefined;
  private readonly logger: Logger;
  private readonly hooks: UpstreamHooks;
  private closing = false;

  constructor(id: string, config: ServerConfig, hooks: UpstreamHooks, logger: Logger, version: string) {
    this.id = id;
    this.config = config;
    this.hooks = hooks;
    this.logger = logger;
    const capabilities: ClientCapabilities = { roots: { listChanged: true }, elicitation: {} };
    if (config.allow_sampling) capabilities.sampling = {};
    this.client = new Client({ name: 'mcphantom', version }, { capabilities });
    this.installHandlers();
  }

  private installHandlers(): void {
    const c = this.client;
    c.setNotificationHandler(ToolListChangedNotificationSchema, () => { this.hooks.onListChanged(this.id, 'tools'); });
    c.setNotificationHandler(ResourceListChangedNotificationSchema, () => { this.hooks.onListChanged(this.id, 'resources'); });
    c.setNotificationHandler(PromptListChangedNotificationSchema, () => { this.hooks.onListChanged(this.id, 'prompts'); });
    c.setNotificationHandler(ResourceUpdatedNotificationSchema, (n) => { this.hooks.onResourceUpdated(this.id, n.params); });
    c.setNotificationHandler(LoggingMessageNotificationSchema, (n) => { this.hooks.onLog(this.id, n.params); });
    c.setRequestHandler(ListRootsRequestSchema, () => this.hooks.listRoots(this.id));
    c.setRequestHandler(ElicitRequestSchema, (r) => this.hooks.elicit(this.id, r.params));
    if (this.config.allow_sampling) {
      c.setRequestHandler(CreateMessageRequestSchema, (r) => this.hooks.createMessage(this.id, r.params));
    }
    c.fallbackRequestHandler = (req) => {
      const reason =
        req.method === 'sampling/createMessage'
          ? 'sampling is disabled for this server (set allow_sampling: true to relay it)'
          : 'method not supported by MCPhantom';
      this.hooks.onRefusedRequest(this.id, req.method, reason);
      return Promise.reject(new McpError(ErrorCode.MethodNotFound, `MCPhantom: ${reason}`));
    };
  }

  async connect(): Promise<void> {
    this.status = 'connecting';
    const transport = this.createTransport();
    this.transport = transport;
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        reject(new Error(`did not complete MCP initialization within ${this.config.startup_timeout_ms} ms`));
      }, this.config.startup_timeout_ms);
    });
    try {
      await Promise.race([this.client.connect(transport), timeout]);
      this.status = 'ready';
      this.client.onclose = () => {
        if (this.status === 'ready' && !this.closing) {
          this.status = 'closed';
          this.hooks.onClose(this.id, 'connection closed');
        }
      };
    } catch (err) {
      this.status = 'failed';
      this.failure = errorMessage(err);
      await transport.close().catch(() => {});
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }

  private createTransport(): Transport {
    const cfg = this.config;
    if (cfg.type === 'http') {
      // The SDK's own class trips exactOptionalPropertyTypes against its Transport interface.
      return new StreamableHTTPClientTransport(new URL(cfg.url), {
        requestInit: { headers: cfg.headers },
        fetch: sizeLimitedFetch(MAX_MESSAGE_BYTES),
        // Never follow a redirect to another origin with the configured credentials attached.
        redirectPolicy: 'same-origin',
      }) as unknown as Transport;
    }
    const baseEnv = cfg.env_inherit === 'all' ? definedEnv(process.env) : getDefaultEnvironment();
    const params = {
      command: cfg.command,
      args: cfg.args,
      env: { ...baseEnv, ...cfg.env },
      stderr: 'pipe' as const,
      ...(cfg.cwd !== undefined ? { cwd: cfg.cwd } : {}),
    };
    const t = new StdioClientTransport(params);
    // Forward the server's stderr, line-prefixed, to ours (MCP clients show it in their logs).
    const stderr = t.stderr;
    if (stderr) {
      let buf = '';
      stderr.on('data', (chunk: Buffer) => {
        buf += chunk.toString('utf8');
        let nl: number;
        while ((nl = buf.indexOf('\n')) >= 0) {
          this.logger.info(`[${this.id}] ${buf.slice(0, nl).replace(/\r$/, '')}`);
          buf = buf.slice(nl + 1);
        }
        if (buf.length > 65_536) {
          this.logger.info(`[${this.id}] ${buf}`);
          buf = '';
        }
      });
    }
    return t;
  }

  get capabilities(): ServerCapabilities {
    return this.client.getServerCapabilities() ?? {};
  }

  get instructions(): string | undefined {
    return this.client.getInstructions();
  }

  get ready(): boolean {
    return this.status === 'ready';
  }

  async listTools(signal?: AbortSignal, limits = DEFAULT_PAGINATION): Promise<Tool[]> {
    if (!this.capabilities.tools) return [];
    return paginate(this.id, 'tools', limits, async (cursor) => {
      const r = await this.client.listTools(cursor === undefined ? {} : { cursor }, signal ? { signal } : {});
      return { items: r.tools, nextCursor: r.nextCursor };
    });
  }

  async listResources(signal?: AbortSignal, limits = DEFAULT_PAGINATION): Promise<Resource[]> {
    if (!this.capabilities.resources) return [];
    return paginate(this.id, 'resources', limits, async (cursor) => {
      const r = await this.client.listResources(cursor === undefined ? {} : { cursor }, signal ? { signal } : {});
      return { items: r.resources, nextCursor: r.nextCursor };
    });
  }

  async listResourceTemplates(signal?: AbortSignal, limits = DEFAULT_PAGINATION): Promise<ResourceTemplate[]> {
    if (!this.capabilities.resources) return [];
    return paginate(this.id, 'resource templates', limits, async (cursor) => {
      const r = await this.client.listResourceTemplates(cursor === undefined ? {} : { cursor }, signal ? { signal } : {});
      return { items: r.resourceTemplates, nextCursor: r.nextCursor };
    });
  }

  async listPrompts(signal?: AbortSignal, limits = DEFAULT_PAGINATION): Promise<Prompt[]> {
    if (!this.capabilities.prompts) return [];
    return paginate(this.id, 'prompts', limits, async (cursor) => {
      const r = await this.client.listPrompts(cursor === undefined ? {} : { cursor }, signal ? { signal } : {});
      return { items: r.prompts, nextCursor: r.nextCursor };
    });
  }

  async close(): Promise<void> {
    this.closing = true;
    if (this.status === 'ready' || this.status === 'connecting') this.status = 'closed';
    await this.client.close().catch(() => {});
  }
}

/**
 * Fetches every page. All pages must be seen: a definition hidden on page N is still delivered to the
 * model if MCPhantom only inspected page 1. Cursor cycles and runaway listings fail the whole listing.
 */
export async function paginate<T>(
  serverId: string,
  what: string,
  limits: PaginationLimits,
  fetchPage: (cursor: string | undefined) => Promise<{ items: T[]; nextCursor?: string | undefined }>,
): Promise<T[]> {
  const items: T[] = [];
  const seen = new Set<string>();
  let bytes = 0;
  let cursor: string | undefined;
  for (let page = 0; ; page++) {
    if (page >= limits.maxPages) throw new Error(`${serverId}: ${what} listing exceeded ${limits.maxPages} pages`);
    const r = await fetchPage(cursor);
    for (const item of r.items) bytes += JSON.stringify(item).length;
    if (bytes > limits.maxBytes) throw new Error(`${serverId}: ${what} listing exceeded ${limits.maxBytes} bytes`);
    items.push(...r.items);
    if (items.length > limits.maxItems) throw new Error(`${serverId}: ${what} listing exceeded ${limits.maxItems} items`);
    if (r.nextCursor === undefined || r.nextCursor === '') return items;
    if (seen.has(r.nextCursor)) throw new Error(`${serverId}: ${what} listing returned a repeated cursor`);
    seen.add(r.nextCursor);
    cursor = r.nextCursor;
  }
}

/** Same bound the SDK applies to a single stdio message. */
export const MAX_MESSAGE_BYTES = 10 * 1024 * 1024;

/**
 * fetch() wrapper bounding what an HTTP upstream can make MCPhantom buffer. JSON responses are capped
 * as a whole; SSE streams are long-lived, so the cap applies to each event (bytes since the last
 * blank line). Without this, a hostile server could stream an unbounded body into memory.
 */
export function sizeLimitedFetch(maxBytes: number, inner: typeof fetch = fetch): (url: string | URL, init?: RequestInit) => Promise<Response> {
  return async (url, init) => {
    const res = await inner(url, init);
    if (!res.body) return res;
    const declared = Number(res.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > maxBytes) {
      await res.body.cancel().catch(() => {});
      throw new Error(`upstream response of ${declared} bytes exceeds the ${maxBytes}-byte limit`);
    }
    const sse = (res.headers.get('content-type') ?? '').includes('text/event-stream');
    let count = 0;
    let prev = 0; // last byte of the previous chunk, to see "\n\n" split across chunks
    const limited = res.body.pipeThrough(
      new TransformStream<Uint8Array, Uint8Array>({
        transform(chunk, ctl) {
          if (sse) {
            // Checked per byte: an oversized event followed by its terminator in the same chunk
            // must not be able to reset the counter before the check runs.
            for (let i = 0; i < chunk.length; i++) {
              const b = chunk[i] as number;
              count = b === 0x0a && prev === 0x0a ? 0 : count + 1;
              if (b !== 0x0d) prev = b;
              if (count > maxBytes) break;
            }
          } else {
            count += chunk.byteLength;
          }
          if (count > maxBytes) {
            ctl.error(new Error(`upstream ${sse ? 'event' : 'response'} exceeds the ${maxBytes}-byte limit`));
            return;
          }
          ctl.enqueue(chunk);
        },
      }),
    );
    return new Response(limited, { status: res.status, statusText: res.statusText, headers: res.headers });
  };
}

function definedEnv(env: NodeJS.ProcessEnv): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(env)) if (v !== undefined) out[k] = v;
  return out;
}
