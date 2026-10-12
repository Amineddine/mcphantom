import { z } from 'zod';

/**
 * Server ids are lowercase and contain no underscore, so the exposed name `<id>__<tool>` splits
 * unambiguously at the first `__`.
 */
export const SERVER_ID_RE = /^[a-z][a-z0-9-]{0,31}$/;
export const ServerIdSchema = z.string().regex(SERVER_ID_RE, 'server ids must match ^[a-z][a-z0-9-]{0,31}$');

/**
 * How a tool's calls and outputs are treated by the taint engine. Anything not stated falls back to the
 * server's `defaults`, then to the secure global default (egress, untrusted output, internal).
 * Server-provided annotations never feed into this: they are controlled by the server.
 */
export const ClassificationSchema = z.strictObject({
  /** What a call can do: `egress` and `exec` can move data off the machine. */
  effect: z.enum(['read', 'write', 'egress', 'exec']).optional(),
  /** Integrity of the tool's output: `untrusted` if a third party can influence it (web, email, ...). */
  integrity: z.enum(['trusted', 'untrusted']).optional(),
  /** Confidentiality floor of the output. Detected credentials always raise it to `secret`. */
  confidentiality: z.enum(['public', 'internal', 'secret']).optional(),
  /** For `write` tools: the directory writes are allowed to stay within. A write whose target is a
   *  remote URL or a path outside this directory is treated as `egress` (DESIGN.md §2, finding A1).
   *  Resolve relative values against the server's `cwd`. */
  workspace: z.string().optional(),
  /** Argument names that name a write destination. Defaults to a built-in set (path, file, dest, ...). */
  path_args: z.array(z.string()).optional(),
});

const common = {
  defaults: ClassificationSchema.default({}),
  tools: z.record(z.string(), ClassificationSchema).default({}),
  /** Relay `sampling/createMessage` from this server to the client. Off by default: sampling lets a
   *  server put arbitrary text straight into the model. */
  allow_sampling: z.boolean().default(false),
  startup_timeout_ms: z.number().int().positive().max(600_000).default(30_000),
};

export const StdioServerSchema = z.strictObject({
  type: z.literal('stdio').default('stdio'),
  command: z.string().min(1),
  args: z.array(z.string()).default([]),
  env: z.record(z.string(), z.string()).default({}),
  cwd: z.string().optional(),
  /** `minimal` (default): only the SDK's allowlist (PATH, HOME, USERPROFILE, ...) plus `env` — the same
   *  environment SDK-based MCP clients give servers, so the gateway never widens what a server sees.
   *  `all`: MCPhantom's full environment, which includes whatever secrets the client process holds. */
  env_inherit: z.enum(['all', 'minimal']).default('minimal'),
  ...common,
});

export const HttpServerSchema = z.strictObject({
  type: z.literal('http'),
  /** Validated after ${VAR} expansion (see load.ts). */
  url: z.string().min(1),
  headers: z.record(z.string(), z.string()).default({}),
  ...common,
});

export const ServerSchema = z.discriminatedUnion('type', [StdioServerSchema, HttpServerSchema]);

export const ConfigSchema = z.strictObject({
  version: z.literal(1),
  servers: z.record(ServerIdSchema, z.preprocess(withDefaultType, ServerSchema)),
  logging: z
    .strictObject({
      /** What is stored for request/response bodies in the event log. */
      payloads: z.enum(['redacted', 'none', 'full']).default('redacted'),
      /** Bytes of serialized payload kept per event (after redaction). */
      max_payload_bytes: z.number().int().min(256).max(1_048_576).default(65_536),
      level: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
    })
    .default({ payloads: 'redacted', max_payload_bytes: 65_536, level: 'info' }),
  retention: z
    .strictObject({
      days: z.number().positive().max(3650).default(14),
      max_mb: z.number().positive().max(100_000).default(256),
    })
    .default({ days: 14, max_mb: 256 }),
  timeouts: z
    .strictObject({
      request_ms: z.number().int().positive().default(60_000),
      tool_call_ms: z.number().int().positive().default(300_000),
    })
    .default({ request_ms: 60_000, tool_call_ms: 300_000 }),
  security: z
    .strictObject({
      /** What to do when MCPhantom's own files are readable by other users. */
      insecure_permissions: z.enum(['fix', 'warn', 'refuse']).default('fix'),
    })
    .default({ insecure_permissions: 'fix' }),
  taint: z
    .strictObject({
      /** The lethal-trifecta invariant: an egress/exec call while the context holds both untrusted and
       *  secret data. `deny` blocks it; `log` only records the decision (audit mode). */
      trifecta: z.enum(['deny', 'log']).default('deny'),
      /** Full-text provenance budget per session (Tier A). Identifier fingerprints are kept separately. */
      max_index_mb: z.number().positive().max(4096).default(32),
    })
    .default({ trifecta: 'deny', max_index_mb: 32 }),
  /** Pass upstream servers' `instructions` to the client (concatenated, one section per server). */
  forward_instructions: z.boolean().default(true),
  /** Override the event-database directory. */
  data_dir: z.string().optional(),
});

function withDefaultType(v: unknown): unknown {
  if (v && typeof v === 'object' && !Array.isArray(v) && !('type' in v)) {
    return { ...v, type: 'url' in v ? 'http' : 'stdio' };
  }
  return v;
}

export type Config = z.infer<typeof ConfigSchema>;
export type Classification = z.infer<typeof ClassificationSchema>;
export type ServerConfig = z.infer<typeof ServerSchema>;
export type StdioServerConfig = z.infer<typeof StdioServerSchema>;
export type HttpServerConfig = z.infer<typeof HttpServerSchema>;
