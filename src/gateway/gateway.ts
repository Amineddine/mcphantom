/* eslint-disable @typescript-eslint/no-deprecated --
 * The low-level `Server` is deprecated only in favour of `McpServer` for *authoring* servers. A proxy
 * must handle raw requests (pagination, _meta, progress, arbitrary schemas), which is exactly the
 * "advanced use case" the SDK keeps `Server` for. */
import { performance } from 'node:perf_hooks';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import type { RequestHandlerExtra, RequestOptions } from '@modelcontextprotocol/sdk/shared/protocol.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import { UriTemplate } from '@modelcontextprotocol/sdk/shared/uriTemplate.js';
import {
  CallToolRequestSchema,
  CompleteRequestSchema,
  ElicitResultSchema,
  ErrorCode,
  GetPromptRequestSchema,
  ListPromptsRequestSchema,
  ListResourcesRequestSchema,
  ListResourceTemplatesRequestSchema,
  ListToolsRequestSchema,
  McpError,
  ReadResourceRequestSchema,
  RootsListChangedNotificationSchema,
  SetLevelRequestSchema,
  SubscribeRequestSchema,
  UnsubscribeRequestSchema,
  type CallToolResult,
  type LoggingLevel,
  type Prompt,
  type RequestMeta,
  type ResourceTemplate,
  type ServerCapabilities,
  type ServerNotification,
  type ServerRequest,
  type Tool,
} from '@modelcontextprotocol/sdk/types.js';
import type { Config } from '../config/schema.js';
import type { EventInput, Store } from '../store/store.js';
import { errorMessage } from '../util/errors.js';
import type { Logger } from '../util/log.js';
import { TaintEngine, type Decision, type IngestResult } from '../taint/engine.js';
import { scanInstructions, scanPrompt, scanTool, type ScanOptions, type ScanResult } from '../scanner/scan.js';
import { RugpullChecker, type PinResult } from '../rugpull/checker.js';
import { PolicyEngine } from '../policy/engine.js';
import { exposeName } from './naming.js';
import { Upstream, type UpstreamHooks } from './upstream.js';

type Extra = RequestHandlerExtra<ServerRequest, ServerNotification>;

interface Route {
  serverId: string;
  name: string;
}

export interface GatewayOptions {
  config: Config;
  store: Store;
  logger: Logger;
  sessionId: string;
  version: string;
  /** Pin checker for rug-pull detection. Omit (or pass an unlocked checker) to disable. */
  rugpull?: RugpullChecker;
}

const LOG_LEVELS: LoggingLevel[] = ['debug', 'info', 'notice', 'warning', 'error', 'critical', 'alert', 'emergency'];

/**
 * The gateway: one downstream MCP server (what the client talks to) multiplexing many upstream MCP
 * clients. Every method served has an explicit handler; anything else is rejected.
 */
export class Gateway {
  readonly server: Server;
  readonly upstreams: ReadonlyMap<string, Upstream>;
  private readonly opts: GatewayOptions;
  private readonly toolRoutes = new Map<string, Route>();
  private readonly promptRoutes = new Map<string, Route>();
  private readonly resourceRoutes = new Map<string, string>();
  /** URIs listed by more than one server: never routed (see listResources). */
  private readonly contestedUris = new Set<string>();
  private readonly templatesByServer = new Map<string, ResourceTemplate[]>();
  private resourcesListed = false;
  private downstreamLogLevel: LoggingLevel | undefined;
  private initialized = false;
  private closed = false;
  private storeWarned = false;
  private resolveDisconnected!: () => void;
  /** Session taint state (one per downstream connection). */
  readonly taint: TaintEngine;
  private readonly scanOpts: ScanOptions;
  private readonly pendingProgress = new WeakMap<Extra, Promise<void>[]>();
  private readonly rugpull: RugpullChecker;
  /** Resolves when the downstream client disconnects (or {@link close} is called). */
  readonly disconnected: Promise<void> = new Promise((r) => {
    this.resolveDisconnected = r;
  });

  private constructor(opts: GatewayOptions, upstreams: Map<string, Upstream>, server: Server) {
    this.opts = opts;
    this.upstreams = upstreams;
    this.server = server;
    this.taint = new TaintEngine(opts.config, new PolicyEngine(opts.config));
    this.scanOpts = { block: opts.config.scan.block };
    this.rugpull = opts.rugpull ?? new RugpullChecker(undefined, false);
  }

  /** Connects all upstreams (in parallel, each with its own startup timeout), then builds the server. */
  static async create(opts: GatewayOptions): Promise<Gateway> {
    const upstreams = new Map<string, Upstream>();
    // Hooks need the gateway instance, which needs the upstreams first; bind late.
    // eslint-disable-next-line prefer-const -- assigned after the hooks that close over it are built
    let self: Gateway | undefined;
    const hooks: UpstreamHooks = {
      onListChanged: (id, kind) => self?.onUpstreamListChanged(id, kind),
      onResourceUpdated: (id, params) => self?.onUpstreamResourceUpdated(id, params),
      onLog: (id, params) => self?.onUpstreamLog(id, params),
      onClose: (id, reason) => self?.onUpstreamClose(id, reason),
      listRoots: (id) => requireSelf(self).relayListRoots(id),
      elicit: (id, params) => requireSelf(self).relayElicit(id, params),
      createMessage: (id, params) => requireSelf(self).relayCreateMessage(id, params),
      onRefusedRequest: (id, method, reason) => {
        self?.record({ kind: 'denied', server: id, method, outcome: 'denied', error: reason });
      },
    };
    for (const [id, cfg] of Object.entries(opts.config.servers)) {
      upstreams.set(id, new Upstream(id, cfg, hooks, opts.logger, opts.version));
    }
    const results = await Promise.allSettled([...upstreams.values()].map(async (u) => {
      await u.connect();
      return u;
    }));
    const events: EventInput[] = [];
    results.forEach((r, i) => {
      const u = [...upstreams.values()][i];
      if (!u) return;
      if (r.status === 'fulfilled') {
        const info = u.client.getServerVersion();
        opts.logger.info(`connected to '${u.id}' (${info?.name ?? '?'} ${info?.version ?? '?'})`);
        events.push({ sessionId: opts.sessionId, kind: 'upstream_connected', server: u.id, payload: { serverInfo: info, capabilities: u.capabilities } });
      } else {
        const msg = errorMessage(r.reason);
        opts.logger.error(`could not start '${u.id}': ${msg}`);
        events.push({ sessionId: opts.sessionId, kind: 'upstream_failed', server: u.id, outcome: 'error', error: msg });
      }
    });

    const ready = [...upstreams.values()].filter((u) => u.ready);
    const capabilities: ServerCapabilities = { tools: { listChanged: true }, logging: {} };
    if (ready.some((u) => u.capabilities.resources)) {
      capabilities.resources = { listChanged: true, subscribe: ready.some((u) => u.capabilities.resources?.subscribe === true) };
    }
    if (ready.some((u) => u.capabilities.prompts)) capabilities.prompts = { listChanged: true };
    if (ready.some((u) => u.capabilities.completions)) capabilities.completions = {};

    // Scan each server's instructions; a flagged section is dropped (it would inject into the model
    // the moment the client reads it), and the drop is logged.
    const rugpull = opts.rugpull ?? new RugpullChecker(undefined, false);
    const instructionParts: [string, string][] = [];
    if (opts.config.forward_instructions) {
      for (const u of ready) {
        const text = u.instructions;
        if (typeof text !== 'string' || text.trim() === '') continue;
        if (opts.config.scan.enabled) {
          const res = scanInstructions(text, { block: opts.config.scan.block });
          if (res.findings.length > 0) {
            const hide = res.flagged && opts.config.scan.mode === 'hide';
            events.push({ sessionId: opts.sessionId, kind: 'scan', server: u.id, method: 'instructions', outcome: hide ? 'hidden' : res.flagged ? 'flagged' : 'noted', payload: { worst: res.worst, findings: res.findings } });
            if (hide) {
              opts.logger.warn(`scanner dropped instructions from '${u.id}': ${res.findings[0]?.detail ?? ''}`);
              continue;
            }
          }
        }
        const pin = rugpull.checkInstructions(u.id, text);
        if ((pin.status === 'changed' || pin.status === 'new') && rugpull.enforcing) {
          const hide = opts.config.rugpull.mode === 'enforce';
          const what = pin.status === 'changed' ? 'instructions changed since approval (possible rug-pull)' : 'instructions added since approval';
          events.push({ sessionId: opts.sessionId, kind: 'rugpull', server: u.id, method: 'instructions', outcome: hide ? 'hidden' : 'flagged', payload: { status: pin.status, fingerprint: pin.fingerprint, pinned: pin.pinned }, error: what });
          if (hide) {
            opts.logger.warn(`rug-pull blocked: instructions from '${u.id}' ${what}`);
            continue;
          }
        }
        instructionParts.push([u.id, text.trim()]);
      }
    }
    const instructions = instructionParts.length
      ? instructionParts.map(([id, t]) => `## Server '${id}' (tools prefixed '${id}__')\n${t}`).join('\n\n')
      : undefined;
    const server = new Server(
      { name: 'mcphantom', version: opts.version, title: 'MCPhantom security gateway' },
      { capabilities, ...(instructions ? { instructions } : {}) },
    );
    const gw = new Gateway(opts, upstreams, server);
    self = gw;
    for (const e of events) gw.append(e);
    gw.installHandlers(capabilities);
    return gw;
  }

  async connect(transport: Transport): Promise<void> {
    await this.server.connect(transport);
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.resolveDisconnected();
    await Promise.allSettled([...this.upstreams.values()].map((u) => u.close()));
    await this.server.close().catch(() => {});
  }

  // -------------------------------------------------------------------------------------------
  // Downstream handlers

  /**
   * Handlers are installed only for advertised capabilities (the SDK enforces this); a method of an
   * unadvertised capability falls through to the fail-closed fallback.
   */
  private installHandlers(caps: ServerCapabilities): void {
    const s = this.server;
    s.oninitialized = () => {
      this.initialized = true;
      const v = s.getClientVersion();
      try {
        this.opts.store.updateSessionClient(this.opts.sessionId, v?.name, v?.version);
      } catch (err) {
        this.warnStore(err);
      }
    };

    s.setRequestHandler(ListToolsRequestSchema, (req, extra) =>
      this.handle('tools/list', {}, req.params, extra, async () => {
        rejectCursor(req.params?.cursor);
        return { tools: await this.listTools(extra.signal) };
      }, (r) => ({ count: r.tools.length })),
    );

    s.setRequestHandler(CallToolRequestSchema, (req, extra) => {
      const exposed = req.params.name;
      return this.handle('tools/call', { name: exposed }, req.params, extra, async (meta) => {
        const route = await this.resolveTool(exposed, extra.signal);
        meta.server = route.serverId;
        const u = this.requireReady(route.serverId);
        const decision = this.taint.decide(route.serverId, route.name, exposed, req.params.arguments ?? {});
        this.recordDecision(decision);
        if (decision.verdict === 'deny') {
          meta.outcome = 'denied';
          return blockedResult(decision);
        }
        if (decision.verdict === 'ask') {
          // Only an explicit approval from the user lets an `ask` through; every other outcome
          // (no elicitation support, decline, cancel, timeout, malformed reply) is a deny.
          const approved = await this.askUser(decision, route.serverId, req.params.arguments ?? {}, extra);
          this.audit({ kind: 'decision', server: route.serverId, name: exposed, method: 'tools/call', outcome: approved ? 'approved' : 'denied', payload: { id: decision.id, ask: approved ? 'approved' : 'refused' } });
          if (!approved) {
            meta.outcome = 'denied';
            return blockedResult(decision);
          }
        }
        // From here the arguments leave the gateway: record them for the cumulative matcher.
        this.taint.sent(exposed, req.params.arguments ?? {});
        const result = (await u.client.callTool(
          forUpstream(req.params, { name: route.name }),
          undefined,
          this.requestOptions(extra, req.params._meta, this.opts.config.timeouts.tool_call_ms),
        )) as CallToolResult;
        await this.flushProgress(extra);
        this.recordIngest(this.taint.ingest('tool', route.serverId, exposed, route.name, result));
        return result;
      });
    });

    if (caps.prompts) this.installPromptHandlers();
    if (caps.resources) this.installResourceHandlers(caps.resources.subscribe === true);
    if (caps.completions) this.installCompletionHandler();
    this.installLoggingHandlers();

    s.fallbackRequestHandler = (req) => {
      this.record({ kind: 'denied', method: req.method, outcome: 'denied', error: 'unknown method' });
      return Promise.reject(new McpError(ErrorCode.MethodNotFound, `MCPhantom: method not supported: ${req.method}`));
    };

    s.onclose = () => {
      this.resolveDisconnected();
    };
  }

  private installPromptHandlers(): void {
    const s = this.server;
    s.setRequestHandler(ListPromptsRequestSchema, (req, extra) =>
      this.handle('prompts/list', {}, req.params, extra, async () => {
        rejectCursor(req.params?.cursor);
        return { prompts: await this.listPrompts(extra.signal) };
      }, (r) => ({ count: r.prompts.length })),
    );

    s.setRequestHandler(GetPromptRequestSchema, (req, extra) =>
      this.handle('prompts/get', { name: req.params.name }, req.params, extra, async (meta) => {
        const route = await this.resolvePrompt(req.params.name, extra.signal);
        meta.server = route.serverId;
        const u = this.requireReady(route.serverId);
        const result = await u.client.getPrompt(
          forUpstream(req.params, { name: route.name }),
          this.requestOptions(extra, req.params._meta, this.opts.config.timeouts.request_ms),
        );
        await this.flushProgress(extra);
        this.recordIngest(this.taint.ingest('prompt', route.serverId, req.params.name, route.name, result));
        return result;
      }),
    );

  }

  private installResourceHandlers(subscribe: boolean): void {
    const s = this.server;
    s.setRequestHandler(ListResourcesRequestSchema, (req, extra) =>
      this.handle('resources/list', {}, req.params, extra, async () => {
        rejectCursor(req.params?.cursor);
        return { resources: await this.listResources(extra.signal) };
      }, (r) => ({ count: r.resources.length })),
    );

    s.setRequestHandler(ListResourceTemplatesRequestSchema, (req, extra) =>
      this.handle('resources/templates/list', {}, req.params, extra, async () => {
        rejectCursor(req.params?.cursor);
        return { resourceTemplates: await this.listResourceTemplates(extra.signal) };
      }, (r) => ({ count: r.resourceTemplates.length })),
    );

    s.setRequestHandler(ReadResourceRequestSchema, (req, extra) =>
      this.handle('resources/read', { name: req.params.uri }, req.params, extra, async (meta) => {
        const serverId = await this.resolveResource(req.params.uri, extra.signal);
        meta.server = serverId;
        const u = this.requireReady(serverId);
        const result = await u.client.readResource(
          forUpstream(req.params, {}),
          this.requestOptions(extra, req.params._meta, this.opts.config.timeouts.request_ms),
        );
        await this.flushProgress(extra);
        // Resources are classified by their server's defaults (no per-URI classification yet).
        this.recordIngest(this.taint.ingest('resource', serverId, req.params.uri, undefined, result));
        return result;
      }),
    );

    if (!subscribe) return;
    for (const [schema, method] of [[SubscribeRequestSchema, 'resources/subscribe'], [UnsubscribeRequestSchema, 'resources/unsubscribe']] as const) {
      s.setRequestHandler(schema, (req, extra) =>
        this.handle(method, { name: req.params.uri }, req.params, extra, async (meta) => {
          const serverId = await this.resolveResource(req.params.uri, extra.signal);
          meta.server = serverId;
          const u = this.requireReady(serverId);
          if (!u.capabilities.resources?.subscribe) {
            throw new McpError(ErrorCode.MethodNotFound, `server '${serverId}' does not support resource subscriptions`);
          }
          const opts = this.requestOptions(extra, undefined, this.opts.config.timeouts.request_ms);
          return method === 'resources/subscribe'
            ? u.client.subscribeResource({ uri: req.params.uri }, opts)
            : u.client.unsubscribeResource({ uri: req.params.uri }, opts);
        }),
      );
    }

  }

  private installCompletionHandler(): void {
    const s = this.server;
    s.setRequestHandler(CompleteRequestSchema, (req, extra) =>
      this.handle('completion/complete', {}, req.params, extra, async (meta) => {
        const ref = req.params.ref;
        let serverId: string;
        let params = req.params;
        if (ref.type === 'ref/prompt') {
          const route = await this.resolvePrompt(ref.name, extra.signal);
          serverId = route.serverId;
          params = { ...req.params, ref: { ...ref, name: route.name } };
        } else {
          serverId = await this.resolveResource(ref.uri, extra.signal);
        }
        meta.server = serverId;
        const u = this.requireReady(serverId);
        if (!u.capabilities.completions) {
          throw new McpError(ErrorCode.MethodNotFound, `server '${serverId}' does not support completions`);
        }
        return u.client.complete(
          forUpstream(params, {}),
          this.requestOptions(extra, undefined, this.opts.config.timeouts.request_ms),
        );
      }),
    );

  }

  private installLoggingHandlers(): void {
    const s = this.server;
    s.setRequestHandler(SetLevelRequestSchema, (req, extra) =>
      this.handle('logging/setLevel', {}, req.params, extra, async () => {
        this.downstreamLogLevel = req.params.level;
        await Promise.allSettled(
          this.readyUpstreams()
            .filter((u) => u.capabilities.logging)
            .map((u) => u.client.setLoggingLevel(req.params.level, { timeout: this.opts.config.timeouts.request_ms })),
        );
        return {};
      }),
    );

    s.setNotificationHandler(RootsListChangedNotificationSchema, async () => {
      await Promise.allSettled(this.readyUpstreams().map((u) => u.client.sendRootsListChanged()));
    });

  }

  /**
   * Runs a handler with event logging and error normalisation. Fails closed: any exception becomes
   * a JSON-RPC error to the client, never a silent pass-through.
   */
  private async handle<T>(
    method: string,
    initial: { name?: string },
    params: unknown,
    _extra: Extra,
    fn: (meta: { server?: string; outcome?: string }) => Promise<T>,
    summarize?: (r: T) => unknown,
  ): Promise<T> {
    const meta: { server?: string; outcome?: string } = {};
    const t0 = performance.now();
    try {
      const result = await fn(meta);
      this.audit({
        kind: 'request', method, name: initial.name, server: meta.server, outcome: meta.outcome ?? 'ok',
        durationMs: performance.now() - t0,
        payload: { params, result: summarize ? summarize(result) : result },
      });
      return result;
    } catch (err) {
      const e = toMcpError(err, meta.server);
      this.record({
        kind: 'request', method, name: initial.name, server: meta.server, outcome: 'error',
        durationMs: performance.now() - t0, payload: { params }, error: e.message,
      });
      throw e;
    }
  }

  private requestOptions(extra: Extra, meta: RequestMeta | undefined, timeout: number): RequestOptions {
    const token = meta?.progressToken;
    const opts: RequestOptions = { signal: extra.signal, timeout, resetTimeoutOnProgress: true };
    if (token !== undefined) {
      const pending: Promise<void>[] = [];
      this.pendingProgress.set(extra, pending);
      opts.onprogress = (p) => {
        pending.push(extra.sendNotification({ method: 'notifications/progress', params: { ...p, progressToken: token } }).catch(() => {}));
      };
    }
    return opts;
  }

  /**
   * Waits for relayed progress notifications of this request to be written before the response is.
   * Without this the response can overtake the last progress message, and the client — which stops
   * listening for a token once its response arrives — silently drops it.
   */
  private async flushProgress(extra: Extra): Promise<void> {
    const pending = this.pendingProgress.get(extra);
    if (pending) await Promise.allSettled(pending);
  }

  // -------------------------------------------------------------------------------------------
  // Listing and routing

  private readyUpstreams(): Upstream[] {
    return [...this.upstreams.values()].filter((u) => u.ready);
  }

  private requireReady(serverId: string): Upstream {
    const u = this.upstreams.get(serverId);
    if (!u) throw new McpError(ErrorCode.InvalidParams, `unknown server '${serverId}'`);
    if (!u.ready) throw new McpError(ErrorCode.InternalError, `server '${serverId}' is not available (${u.status}${u.failure ? ': ' + u.failure : ''})`);
    return u;
  }

  /** Lists every ready upstream, all pages. A server whose listing fails contributes nothing. */
  private async listTools(signal?: AbortSignal): Promise<Tool[]> {
    const out: Tool[] = [];
    const lists = await this.perServer((u) => u.listTools(signal), 'tools/list');
    for (const [u, tools] of lists) {
      for (const [k, r] of this.toolRoutes) if (r.serverId === u.id) this.toolRoutes.delete(k);
      for (const tool of tools) {
        if (tool.execution?.taskSupport === 'required') {
          this.record({ kind: 'warning', server: u.id, name: tool.name, error: 'tool requires task-based execution, which MCPhantom does not support; hidden' });
          continue;
        }
        const exposed = exposeName(u.id, tool.name);
        if (!exposed) {
          this.record({ kind: 'warning', server: u.id, name: tool.name, error: 'tool name cannot be namespaced within MCP name limits; hidden' });
          continue;
        }
        const { execution: _execution, ...rest } = tool;
        // Per-tool fail-closed: a malformed/hostile definition (e.g. a schema deep enough to overflow
        // the canonicaliser) hides only that tool, never the whole listing.
        if (this.inspectBlocks(() => this.scanBlocks(scanTool(rest, this.scanOpts), 'tool', u.id, exposed) || this.rugpullBlocks(this.rugpull.checkTool(u.id, rest), 'tool', u.id, exposed), 'tool', u.id, exposed)) continue;
        this.toolRoutes.set(exposed, { serverId: u.id, name: tool.name });
        out.push({ ...rest, name: exposed });
      }
    }
    return out;
  }

  private async listPrompts(signal?: AbortSignal): Promise<Prompt[]> {
    const out: Prompt[] = [];
    const lists = await this.perServer((u) => u.listPrompts(signal), 'prompts/list');
    for (const [u, prompts] of lists) {
      for (const [k, r] of this.promptRoutes) if (r.serverId === u.id) this.promptRoutes.delete(k);
      for (const p of prompts) {
        const exposed = exposeName(u.id, p.name);
        if (!exposed) {
          this.record({ kind: 'warning', server: u.id, name: p.name, error: 'prompt name cannot be namespaced; hidden' });
          continue;
        }
        if (this.inspectBlocks(() => this.scanBlocks(scanPrompt({ ...p, name: exposed }, this.scanOpts), 'prompt', u.id, exposed) || this.rugpullBlocks(this.rugpull.checkPrompt(u.id, p), 'prompt', u.id, exposed), 'prompt', u.id, exposed)) continue;
        this.promptRoutes.set(exposed, { serverId: u.id, name: p.name });
        out.push({ ...p, name: exposed });
      }
    }
    return out;
  }

  private async listResources(signal?: AbortSignal) {
    const lists = await this.perServer((u) => u.listResources(signal), 'resources/list');
    this.resourceRoutes.clear();
    this.contestedUris.clear();
    // A URI claimed by two servers is resource shadowing: one server answering reads meant for
    // another. Neither claim is trusted; the URI is hidden and reads of it are refused.
    const owners = new Map<string, Set<string>>();
    for (const [u, resources] of lists) {
      for (const r of resources) owners.set(r.uri, (owners.get(r.uri) ?? new Set()).add(u.id));
    }
    const out = [];
    for (const [u, resources] of lists) {
      for (const r of resources) {
        const claimants = owners.get(r.uri);
        if (claimants && claimants.size > 1) {
          if (!this.contestedUris.has(r.uri)) {
            this.contestedUris.add(r.uri);
            this.record({ kind: 'warning', server: u.id, name: r.uri, error: `resource URI listed by several servers (${[...claimants].join(', ')}); hidden and not routable` });
          }
          continue;
        }
        this.resourceRoutes.set(r.uri, u.id);
        out.push(r);
      }
    }
    this.resourcesListed = true;
    return out;
  }

  private async listResourceTemplates(signal?: AbortSignal): Promise<ResourceTemplate[]> {
    const lists = await this.perServer((u) => u.listResourceTemplates(signal), 'resources/templates/list');
    const out: ResourceTemplate[] = [];
    for (const [u, templates] of lists) {
      this.templatesByServer.set(u.id, templates);
      out.push(...templates);
    }
    return out;
  }

  private async perServer<T>(fn: (u: Upstream) => Promise<T>, method: string): Promise<[Upstream, T][]> {
    const ready = this.readyUpstreams();
    const settled = await Promise.allSettled(ready.map(fn));
    const out: [Upstream, T][] = [];
    settled.forEach((r, i) => {
      const u = ready[i];
      if (!u) return;
      if (r.status === 'fulfilled') out.push([u, r.value]);
      else {
        const msg = errorMessage(r.reason);
        this.opts.logger.warn(`${method} failed for '${u.id}': ${msg}`);
        this.record({ kind: 'warning', server: u.id, method, outcome: 'error', error: msg });
      }
    });
    return out;
  }

  private async resolveTool(exposed: string, signal?: AbortSignal): Promise<Route> {
    let route = this.toolRoutes.get(exposed);
    if (!route) {
      // The client may call a tool without listing first (or after a list_changed). Re-list once.
      await this.listTools(signal);
      route = this.toolRoutes.get(exposed);
    }
    if (!route) throw new McpError(ErrorCode.InvalidParams, `unknown tool: ${exposed}`);
    return route;
  }

  private async resolvePrompt(exposed: string, signal?: AbortSignal): Promise<Route> {
    let route = this.promptRoutes.get(exposed);
    if (!route) {
      await this.listPrompts(signal);
      route = this.promptRoutes.get(exposed);
    }
    if (!route) throw new McpError(ErrorCode.InvalidParams, `unknown prompt: ${exposed}`);
    return route;
  }

  /**
   * Resource URIs are not namespaced (rewriting them would break servers and clients that interpret
   * them). Routing: an exact URI from a listing, else a unique template match, else the only server
   * that offers resources. Anything ambiguous is refused rather than guessed.
   */
  private async resolveResource(uri: string, signal?: AbortSignal): Promise<string> {
    if (!this.resourcesListed) await Promise.all([this.listResources(signal), this.listResourceTemplates(signal)]);
    if (this.contestedUris.has(uri)) throw new McpError(ErrorCode.InvalidParams, `resource URI is listed by several servers; refusing to guess: ${uri}`);
    const exact = this.resourceRoutes.get(uri);
    if (exact) return exact;
    if (this.templatesByServer.size === 0) await this.listResourceTemplates(signal);
    const candidates = new Set<string>();
    for (const [serverId, templates] of this.templatesByServer) {
      for (const t of templates) {
        try {
          if (new UriTemplate(t.uriTemplate).match(uri)) candidates.add(serverId);
        } catch {
          // Malformed template from the server: ignore it for routing.
        }
      }
    }
    if (candidates.size === 1) return [...candidates][0] as string;
    if (candidates.size > 1) throw new McpError(ErrorCode.InvalidParams, `resource URI matches templates of several servers (${[...candidates].join(', ')}): ${uri}`);
    // An unlisted, untemplated URI is refused by default: guessing a route sends the request (and any
    // credentials or paths in the URI) to a server that never claimed it. Opt-in for servers that hand
    // out resource links they do not list.
    if (this.opts.config.resources.unrouted === 'sole-server') {
      const withResources = this.readyUpstreams().filter((u) => u.capabilities.resources);
      if (withResources.length === 1 && withResources[0]) return withResources[0].id;
    }
    throw new McpError(ErrorCode.InvalidParams, `no server provides resource: ${uri}`);
  }

  // -------------------------------------------------------------------------------------------
  // Upstream events and server→client relays

  private onUpstreamListChanged(serverId: string, kind: 'tools' | 'resources' | 'prompts'): void {
    this.record({ kind: 'notification', server: serverId, method: `notifications/${kind}/list_changed` });
    if (kind === 'resources') this.resourcesListed = false;
    if (!this.initialized) return;
    const send = kind === 'tools' ? this.server.sendToolListChanged() : kind === 'resources' ? this.server.sendResourceListChanged() : this.server.sendPromptListChanged();
    send.catch(() => {});
  }

  private onUpstreamResourceUpdated(serverId: string, params: { uri: string }): void {
    if (this.resourceRoutes.get(params.uri) !== undefined && this.resourceRoutes.get(params.uri) !== serverId) return;
    if (this.initialized) this.server.sendResourceUpdated(params).catch(() => {});
  }

  private onUpstreamLog(serverId: string, params: { level: LoggingLevel; logger?: string | undefined; data?: unknown }): void {
    if (!this.initialized) return;
    if (this.downstreamLogLevel && LOG_LEVELS.indexOf(params.level) < LOG_LEVELS.indexOf(this.downstreamLogLevel)) return;
    const logger = params.logger ? `${serverId}/${params.logger}` : serverId;
    this.server.sendLoggingMessage({ level: params.level, logger, data: params.data }).catch(() => {});
  }

  private onUpstreamClose(serverId: string, reason: string): void {
    this.opts.logger.warn(`upstream '${serverId}' closed: ${reason}`);
    this.record({ kind: 'upstream_closed', server: serverId, error: reason });
    for (const [k, r] of this.toolRoutes) if (r.serverId === serverId) this.toolRoutes.delete(k);
    for (const [k, r] of this.promptRoutes) if (r.serverId === serverId) this.promptRoutes.delete(k);
    if (this.initialized && !this.closed) this.server.sendToolListChanged().catch(() => {});
  }

  private async relayListRoots(serverId: string) {
    if (!this.server.getClientCapabilities()?.roots) {
      throw new McpError(ErrorCode.MethodNotFound, 'the MCP client does not support roots');
    }
    this.audit({ kind: 'request', server: serverId, method: 'roots/list', outcome: 'relayed' });
    return this.server.listRoots(undefined, { timeout: this.opts.config.timeouts.request_ms });
  }

  private async relayElicit(serverId: string, params: Record<string, unknown>) {
    if (!this.server.getClientCapabilities()?.elicitation) {
      throw new McpError(ErrorCode.MethodNotFound, 'the MCP client does not support elicitation');
    }
    this.audit({ kind: 'request', server: serverId, method: 'elicitation/create', outcome: 'relayed', payload: params });
    // Elicitation waits on a human; use the long timeout.
    return this.server.request({ method: 'elicitation/create', params: params as never }, ElicitResultSchema, { timeout: this.opts.config.timeouts.tool_call_ms });
  }

  private async relayCreateMessage(serverId: string, params: Parameters<Server['createMessage']>[0]) {
    if (!this.server.getClientCapabilities()?.sampling) {
      throw new McpError(ErrorCode.MethodNotFound, 'the MCP client does not support sampling');
    }
    this.audit({ kind: 'request', server: serverId, method: 'sampling/createMessage', outcome: 'relayed', payload: params });
    return this.server.createMessage(params, { timeout: this.opts.config.timeouts.tool_call_ms });
  }

  // -------------------------------------------------------------------------------------------
  // Event log

  /**
   * Applies a scan verdict to a tool/prompt at list time. Returns true if the subject must be hidden.
   * Findings are always recorded; hiding happens only when scanning is enabled, the mode is `hide`,
   * and the verdict is at or above the configured block severity.
   */
  private scanBlocks(result: ScanResult, kind: 'tool' | 'prompt' | 'instructions', server: string, name: string): boolean {
    if (!this.opts.config.scan.enabled || result.findings.length === 0) return false;
    const hide = result.flagged && this.opts.config.scan.mode === 'hide';
    this.record({
      kind: 'scan', server, name, method: kind,
      outcome: hide ? 'hidden' : result.flagged ? 'flagged' : 'noted',
      payload: { worst: result.worst, findings: result.findings },
      error: hide ? `${kind} hidden: ${result.findings[0]?.detail ?? 'scanner finding'}` : undefined,
    });
    if (hide) this.opts.logger.warn(`scanner hid ${kind} '${name}' from '${server}': ${result.findings[0]?.detail ?? ''}`);
    return hide;
  }

  /**
   * Applies a pin check at list time. A `changed` pin is a rug-pull; a `new` item appeared after the
   * lockfile was approved. In `enforce` mode either is hidden; in `observe` mode it is kept and the
   * change recorded. `match`/`unpinned` are silent (unpinned = no lockfile yet).
   */
  /** Runs the per-item inspections; any thrown error hides the item and is logged (fail-closed). */
  private inspectBlocks(fn: () => boolean, kind: 'tool' | 'prompt', server: string, name: string): boolean {
    try {
      return fn();
    } catch (err) {
      this.record({ kind: 'warning', server, name, method: kind, outcome: 'hidden', error: `could not inspect ${kind}; hidden (${errorMessage(err)})` });
      this.opts.logger.warn(`hiding ${kind} '${name}' from '${server}': inspection failed: ${errorMessage(err)}`);
      return true;
    }
  }

  private rugpullBlocks(result: PinResult, kind: 'tool' | 'prompt' | 'instructions', server: string, name: string): boolean {
    if (result.status === 'match' || result.status === 'unpinned') return false;
    const hide = this.opts.config.rugpull.mode === 'enforce';
    const what = result.status === 'changed' ? 'definition changed since it was approved (possible rug-pull)' : 'not in the approved lockfile (added since approval)';
    this.record({
      kind: 'rugpull', server, name, method: kind,
      outcome: hide ? 'hidden' : 'flagged',
      payload: { status: result.status, fingerprint: result.fingerprint, pinned: result.pinned },
      error: `${kind} ${what}`,
    });
    this.opts.logger.warn(`rug-pull ${hide ? 'blocked' : 'detected'}: ${kind} '${name}' from '${server}' ${what}`);
    return hide;
  }

  private recordDecision(d: Decision): void {
    this.audit({
      kind: 'decision', server: d.server, name: d.tool, method: 'tools/call',
      outcome: d.verdict === 'deny' ? 'denied' : d.verdict === 'ask' ? 'ask' : d.rule ? 'flagged' : 'allowed',
      payload: d,
    });
  }

  /**
   * Asks the user to confirm a call through MCP elicitation. Returns true only for an explicit
   * `accept` with `approve: true`. The prompt names the tool, the rule and the argument *names* — not
   * their values, which may be large or carry attacker-controlled text.
   */
  private async askUser(d: Decision, serverId: string, args: unknown, extra: Extra): Promise<boolean> {
    if (!this.server.getClientCapabilities()?.elicitation) return false;
    const argNames = args && typeof args === 'object' ? Object.keys(args) : [];
    try {
      const r = await this.server.elicitInput(
        {
          message:
            `MCPhantom: '${d.tool}' (server '${serverId}') needs your confirmation.\n` +
            `Reason: ${d.reason}\nArguments: ${argNames.length ? argNames.join(', ') : '(none)'}\nAllow this one call?`,
          requestedSchema: { type: 'object', properties: { approve: { type: 'boolean', title: 'Allow this call' } }, required: ['approve'] },
        },
        { timeout: this.opts.config.timeouts.tool_call_ms, signal: extra.signal },
      );
      return r.action === 'accept' && (r.content as { approve?: unknown } | undefined)?.approve === true;
    } catch {
      return false;
    }
  }

  private recordIngest(r: IngestResult): void {
    this.audit({
      kind: 'taint', server: r.ref.server, name: r.ref.source, method: r.ref.kind,
      payload: { output: r.ref, secretsDetected: r.secretsDetected, identifiers: r.identifiers, contextBefore: r.contextBefore, contextAfter: r.contextAfter },
    });
    for (const e of r.evictions) {
      this.audit({ kind: 'eviction', server: e.output.server, name: e.output.source, payload: { output: e.output, bytes: e.bytes, stats: this.taint.indexStats } });
    }
  }

  /** Best-effort event (warnings, notifications): a write failure is reported, never fatal. */
  private record(e: Omit<EventInput, 'sessionId'>): boolean {
    return this.append({ ...e, sessionId: this.opts.sessionId });
  }

  /**
   * An event that audits a request crossing the gateway (a call decision, a relayed request, a result
   * entering the model's context). With `logging.on_failure: deny` a failed write throws, so the
   * request is refused or its result withheld — nothing passes unaudited. With `warn` (default) it is
   * reported once and the request continues, as for any other event.
   */
  private audit(e: Omit<EventInput, 'sessionId'>): void {
    if (this.record(e) || this.opts.config.logging.on_failure !== 'deny') return;
    throw new McpError(ErrorCode.InternalError, 'MCPhantom: the audit log could not be written, so this request was refused (logging.on_failure: deny)');
  }

  private append(e: EventInput): boolean {
    try {
      this.opts.store.append(e);
      return true;
    } catch (err) {
      this.warnStore(err);
      return false;
    }
  }

  private warnStore(err: unknown): void {
    if (this.storeWarned) return;
    this.storeWarned = true;
    this.opts.logger.warn(`event log write failed (further failures suppressed): ${errorMessage(err)}`);
  }
}

function requireSelf(g: Gateway | undefined): Gateway {
  if (!g) throw new McpError(ErrorCode.InternalError, 'MCPhantom gateway is still starting');
  return g;
}

/** The gateway returns every page at once, so a cursor from the client can only be bogus. */
function rejectCursor(cursor: string | undefined): void {
  if (cursor !== undefined) throw new McpError(ErrorCode.InvalidParams, 'invalid cursor');
}

/**
 * The SDK client allocates its own progress token when `onprogress` is set; forwarding the client's
 * token upstream as well would make the server report progress under a token nobody tracks.
 */
function forUpstream<P extends { _meta?: RequestMeta | undefined }>(params: P, overrides: Partial<P>): P {
  const { _meta: meta, ...rest } = params;
  const out = { ...rest, ...overrides } as P;
  if (meta) {
    const { progressToken: _token, ...metaRest } = meta;
    if (Object.keys(metaRest).length > 0) out._meta = metaRest;
  }
  return out;
}

/**
 * An error whose `message` is sent on the wire verbatim. The SDK client prefixes "MCP error <code>: "
 * to every error it receives; `McpError` would add a second prefix when re-thrown, so upstream
 * errors are rebuilt with exactly the message the upstream server sent.
 */
export class WireError extends Error {
  readonly code: number;
  readonly data: unknown;
  constructor(code: number, message: string, data?: unknown) {
    super(message);
    this.code = code;
    this.data = data;
  }
}

function toMcpError(err: unknown, serverId: string | undefined): Error & { code: number } {
  if (err instanceof McpError) {
    const prefix = `MCP error ${err.code}: `;
    const wire = err.message.startsWith(prefix) ? err.message.slice(prefix.length) : err.message;
    return new WireError(err.code, wire, err.data);
  }
  const where = serverId ? ` (server '${serverId}')` : '';
  return new McpError(ErrorCode.InternalError, `MCPhantom: request failed${where}: ${errorMessage(err)}`);
}


/**
 * What the model sees when a call is blocked: an ordinary tool error (so the agent can continue and
 * tell the user), naming the rule and the decision id the user can look up with `mcphantom trace`.
 */
export function blockedResult(d: Decision): CallToolResult {
  return {
    isError: true,
    content: [
      {
        type: 'text',
        text:
          `MCPhantom blocked this call (rule: ${d.rule ?? 'policy'}, decision ${d.id}). ` +
          (d.rule === 'trifecta'
            ? 'This session has handled untrusted content and secret data, so tools that can send data out are disabled for it. '
            : d.verdict === 'ask'
              ? 'This call needs the user’s confirmation, which was not given (or the client cannot ask). '
              : `It is not allowed by the configured policy: ${d.reason}. `) +
          'Tell the user; they can inspect it with "mcphantom trace".',
      },
    ],
  };
}
