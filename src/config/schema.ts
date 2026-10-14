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
const RuleSchema = z
  .strictObject({ deny: z.string().optional(), ask: z.string().optional(), allow: z.string().optional() })
  .refine((r) => [r.deny, r.ask, r.allow].filter((x) => x !== undefined).length === 1, { message: 'each rule must have exactly one of deny/ask/allow' });

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
  /** Per-tool policy rules, evaluated in order; strongest effect wins (deny > ask > allow). Each entry
   *  has exactly one of deny/ask/allow mapping to a CEL expression over `arg` and `context`. */
  rules: z.array(RuleSchema).optional(),
});

const common = {
  defaults: ClassificationSchema.default({}),
  tools: z.record(z.string(), ClassificationSchema).default({}),
  /** Relay `sampling/createMessage` from this server to the client. Off by default: sampling lets a
   *  server put arbitrary text straight into the model. */
  allow_sampling: z.boolean().default(false),
  /** The highest confidentiality this server may receive in tool-call arguments (DESIGN.md §2): every
   *  `tools/call` sends its arguments to the server's operator, whatever the tool's effect. Unset: no
   *  bound (only policy rules and the trifecta invariant apply). */
  may_receive: z.enum(['public', 'internal', 'secret']).optional(),
  /** How `may_receive` is checked. `evidence` (default): deny when an argument carries a credential or is
   *  attributed by Layer 2 to an output labelled above the bound — precise, but bypassable by encodings
   *  attribution misses. `context`: also deny whenever the session context label is above the bound —
   *  sound, but blocks every call to this server once such data has been read. */
  may_receive_mode: z.enum(['evidence', 'context']).default('evidence'),
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
      /** What happens when an event cannot be written to the audit log. `warn`: report it once and keep
       *  serving (the log is an audit trail). `deny`: fail closed — a request whose decision or
       *  result cannot be audited is refused, and its result is withheld from the client. */
      on_failure: z.enum(['warn', 'deny']).default('warn'),
    })
    .default({ payloads: 'redacted', max_payload_bytes: 65_536, level: 'info', on_failure: 'warn' }),
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
  secrets: z
    .strictObject({
      /** Entropy-based "possible secret" detection (src/secrets/entropy.ts): random-looking tokens with
       *  no known format. It cannot tell a key from a random id (measured: `npm run bench:entropy`). */
      entropy: z
        .strictObject({
          enabled: z.boolean().default(true),
          /** Effect of a random-shaped hit in a tool output on the session label. `record` (default):
           *  logged as a possible secret, label unchanged. `internal` / `secret`: raise the output's
           *  confidentiality to at least that level. Identifier-shaped hits (hex, UUIDs, digests,
           *  type-prefixed ids, values of id-named fields) never raise the label. */
          on_hit: z.enum(['record', 'internal', 'secret']).default('record'),
          /** Redact possible secrets (both shapes) in the event log. */
          redact: z.boolean().default(true),
        })
        .default({ enabled: true, on_hit: 'record', redact: true }),
    })
    .default({ entropy: { enabled: true, on_hit: 'record', redact: true } }),
  scan: z
    .strictObject({
      enabled: z.boolean().default(true),
      /** Minimum finding severity that hides a tool/prompt (or strips an instructions section). */
      block: z.enum(['low', 'medium', 'high']).default('medium'),
      /** `hide`: remove the flagged tool from tools/list. `warn`: keep it but record the findings. */
      mode: z.enum(['hide', 'warn']).default('hide'),
    })
    .default({ enabled: true, block: 'medium', mode: 'hide' }),
  rugpull: z
    .strictObject({
      /** `enforce`: hide tools/prompts whose definition changed from the pin, or that are new since
       *  the lockfile was approved. `observe`: allow them but record the change. With no lockfile,
       *  nothing is pinned and this has no effect until `mcphantom approve` creates one. */
      mode: z.enum(['enforce', 'observe']).default('enforce'),
      /** What to do when a present lockfile fails HMAC verification (tampered, or wrong key/machine). */
      on_bad_signature: z.enum(['refuse', 'warn']).default('refuse'),
    })
    .default({ mode: 'enforce', on_bad_signature: 'refuse' }),
  /** Named exceptions that lift the global trifecta invariant for a specific tool when a condition
   *  holds. Each is audited on every decision it affects. */
  declassify: z
    .array(
      z.strictObject({
        id: z.string().min(1),
        tool: z.string().min(1),
        when: z.string().min(1),
        reason: z.string().min(1),
      }),
    )
    .default([]),
  resources: z
    .strictObject({
      /** Routing of a resource URI that no server listed and no template matches. `deny` (default):
       *  refuse it. `sole-server`: send it to the only resource-capable server, if there is exactly one
       *  (useful for servers that hand out resource links they do not list). */
      unrouted: z.enum(['deny', 'sole-server']).default('deny'),
    })
    .default({ unrouted: 'deny' }),
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
export type Rule = z.infer<typeof RuleSchema>;
export type Declassify = z.infer<typeof ConfigSchema>['declassify'];
export type ServerConfig = z.infer<typeof ServerSchema>;
export type StdioServerConfig = z.infer<typeof StdioServerSchema>;
export type HttpServerConfig = z.infer<typeof HttpServerSchema>;
