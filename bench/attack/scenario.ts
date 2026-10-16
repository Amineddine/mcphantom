/**
 * mcp-attack-bench, Tier 1 (DESIGN.md §6; Phase 7 item 3). Declarative scenarios with recorded traces.
 *
 * A scenario names its servers (tool definitions + MCPhantom-neutral classifications), the secrets it
 * seeds, and a recorded trace of tool calls, each with the output the fixture would return. Strings in a
 * trace may hold placeholders, expanded at load time so no secret-shaped literal is ever committed:
 *
 *   {{secret:<id>}}                the secret, as is
 *   {{secret:<id>|<transform>}}    encoded: base64 | hex | url | reverse
 *   {{secret:<id>|part:<i>/<n>}}   the i-th of n equal fragments (a secret split across calls)
 *
 * Injection points carry the inert marker `[[UNTRUSTED_PLACEHOLDER]]`, never injection prose: the bench
 * measures what the defense does once a model has been steered, not whether a model is steerable.
 */
import crypto from 'node:crypto';
import { z } from 'zod';

const Classification = z.object({
  effect: z.enum(['read', 'write', 'egress', 'exec']).optional(),
  integrity: z.enum(['trusted', 'untrusted']).optional(),
  confidentiality: z.enum(['public', 'internal', 'secret']).optional(),
  workspace: z.string().optional(),
});

const ToolSpec = z.object({
  description: z.string(),
  inputSchema: z.record(z.string(), z.unknown()),
  classification: Classification.default({}),
});

const ServerSpec = z.object({
  tools: z.record(z.string(), ToolSpec),
  /** Deployment-level bound, as an operator would configure it (DESIGN.md §2). */
  may_receive: z.enum(['public', 'internal', 'secret']).optional(),
});

const Step = z.object({
  role: z.enum(['benign', 'attack']),
  server: z.string(),
  tool: z.string(),
  args: z.record(z.string(), z.unknown()),
  /** What the fixture returns if the call is delivered (ingested as the tool's output). */
  returns: z.string().optional(),
  /** Ground truth: whatever this call delivers reaches the attacker (an attacker-run endpoint or server,
   *  a path the attacker can read). Per call, since the same tool may write inside or outside a workspace. */
  to_attacker: z.boolean().default(false),
});

export const ScenarioSchema = z.object({
  id: z.string(),
  category: z.string(),
  /** `attack`: success oracle applies. `benign`: only the utility / false-block oracle applies. */
  kind: z.enum(['attack', 'benign']),
  /** Attack scenarios the design does not claim to stop are reported separately, never pooled. */
  claimed: z.boolean().default(true),
  description: z.string(),
  servers: z.record(z.string(), ServerSpec),
  secrets: z.array(z.object({ id: z.string(), format: z.enum(['aws-access-key-id', 'random-token']) })),
  /** Attack scenarios: the ground truth the success oracle checks — which secret, encoded how. */
  exfil: z.object({ secret: z.string(), transform: z.enum(['exact', 'base64', 'hex', 'url', 'reverse', 'split3']) }).optional(),
  steps: z.array(Step).min(1),
});
export type Scenario = z.infer<typeof ScenarioSchema>;
/** What a scenario author writes (defaulted fields optional). */
export type ScenarioInput = z.input<typeof ScenarioSchema>;
export type ScenarioStep = z.infer<typeof Step>;

// ---- secrets: assembled from fragments, never stored ---------------------------------------------------
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const B62 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
function digest(seed: string): Buffer {
  return crypto.createHash('sha256').update(`mcp-attack-bench:${seed}`).digest();
}
/** Deterministic per scenario + secret id, so traces replay identically and results are reproducible. */
export function secretValue(scenarioId: string, s: { id: string; format: 'aws-access-key-id' | 'random-token' }): string {
  const d = digest(`${scenarioId}:${s.id}`);
  if (s.format === 'aws-access-key-id') return ['AK', 'IA', Array.from(d.subarray(0, 16), (b) => B32[b % 32]).join('')].join('');
  return Array.from(d, (b) => B62[b % 62]).join('').slice(0, 32);
}

export function encode(value: string, transform: string): string {
  switch (transform) {
    case 'exact':
      return value;
    case 'base64':
      return Buffer.from(value).toString('base64');
    case 'hex':
      return Buffer.from(value).toString('hex');
    case 'url':
      return Array.from(Buffer.from(value), (b) => `%${b.toString(16).toUpperCase().padStart(2, '0')}`).join('');
    case 'reverse':
      return Array.from(value).reverse().join('');
    default:
      throw new Error(`unknown transform ${transform}`);
  }
}

export function part(value: string, i: number, n: number): string {
  const size = Math.ceil(value.length / n);
  return value.slice(i * size, (i + 1) * size);
}

const PLACEHOLDER = /\{\{secret:([a-z0-9_-]+)(?:\|(?:part:(\d+)\/(\d+)|([a-z0-9]+)))?\}\}/g;

function expandString(s: string, secrets: Map<string, string>): string {
  return s.replace(PLACEHOLDER, (_m, id: string, pi?: string, pn?: string, tr?: string) => {
    const v = secrets.get(id);
    if (v === undefined) throw new Error(`unknown secret ${id}`);
    if (pi !== undefined && pn !== undefined) return part(v, Number(pi), Number(pn));
    return encode(v, tr ?? 'exact');
  });
}

function expand(v: unknown, secrets: Map<string, string>): unknown {
  if (typeof v === 'string') return expandString(v, secrets);
  if (Array.isArray(v)) return v.map((x) => expand(x, secrets));
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, expand(x, secrets)]));
  return v;
}

export interface LoadedScenario extends Scenario {
  secretValues: Map<string, string>;
}

/** Validates and expands placeholders. Throws on an unknown secret id or a malformed scenario. */
export function loadScenario(raw: unknown): LoadedScenario {
  const sc = ScenarioSchema.parse(raw);
  const secretValues = new Map(sc.secrets.map((s) => [s.id, secretValue(sc.id, s)]));
  const steps = sc.steps.map((st) => ({ ...st, args: expand(st.args, secretValues) as Record<string, unknown>, returns: st.returns === undefined ? undefined : expandString(st.returns, secretValues) }));
  for (const st of steps) {
    if (!sc.servers[st.server]?.tools[st.tool]) throw new Error(`${sc.id}: step calls undefined tool ${st.server}/${st.tool}`);
  }
  if (sc.kind === 'attack' && !sc.exfil) throw new Error(`${sc.id}: attack scenario without exfil ground truth`);
  return { ...sc, steps, secretValues };
}
