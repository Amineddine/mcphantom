import type { Prompt, Tool } from '@modelcontextprotocol/sdk/types.js';

/**
 * A span of model-visible text with where it came from. Everything a tool definition puts into the
 * model's context is in scope for scanning: the name, title, description, every description / enum /
 * default / const string anywhere in the input and output JSON Schemas, and annotation titles. Fields
 * the model never sees (icons, _meta transport data) are not scanned.
 */
export interface TextSpan {
  /** Dotted location, e.g. `description` or `inputSchema.properties.path.description`. */
  where: string;
  text: string;
}

const MAX_SPANS = 2000;
const MAX_DEPTH = 24;

export function toolSpans(tool: Tool): TextSpan[] {
  const spans: TextSpan[] = [];
  push(spans, 'name', tool.name);
  push(spans, 'title', tool.title);
  push(spans, 'description', tool.description);
  const ann = tool.annotations as { title?: unknown } | undefined;
  if (ann && typeof ann.title === 'string') push(spans, 'annotations.title', ann.title);
  schemaSpans(tool.inputSchema, 'inputSchema', spans);
  schemaSpans(tool.outputSchema, 'outputSchema', spans);
  return spans;
}

export function promptSpans(prompt: Prompt): TextSpan[] {
  const spans: TextSpan[] = [];
  push(spans, 'name', prompt.name);
  push(spans, 'title', prompt.title);
  push(spans, 'description', prompt.description);
  for (const [i, arg] of (prompt.arguments ?? []).entries()) {
    push(spans, `arguments[${i}].name`, arg.name);
    push(spans, `arguments[${i}].description`, arg.description);
  }
  return spans;
}

export function instructionsSpan(instructions: string | undefined): TextSpan[] {
  return instructions ? [{ where: 'instructions', text: instructions }] : [];
}

/**
 * Pulls human-readable strings out of a JSON Schema: `description`, `title`, enum values, `const`,
 * `default`, and `examples`. These reach the model and are a documented poisoning vector (hidden
 * instructions live in a parameter's description as readily as in the tool's).
 */
function schemaSpans(schema: unknown, base: string, spans: TextSpan[], depth = 0): void {
  if (schema === null || typeof schema !== 'object' || depth > MAX_DEPTH || spans.length >= MAX_SPANS) return;
  if (Array.isArray(schema)) {
    schema.forEach((s, i) => { schemaSpans(s, `${base}[${i}]`, spans, depth + 1); });
    return;
  }
  const obj = schema as Record<string, unknown>;
  for (const key of ['description', 'title', '$comment'] as const) {
    if (typeof obj[key] === 'string') push(spans, `${base}.${key}`, obj[key]);
  }
  if (typeof obj.const === 'string') push(spans, `${base}.const`, obj.const);
  if (typeof obj.default === 'string') push(spans, `${base}.default`, obj.default);
  for (const key of ['enum', 'examples'] as const) {
    if (Array.isArray(obj[key])) for (const [i, v] of (obj[key] as unknown[]).entries()) if (typeof v === 'string') push(spans, `${base}.${key}[${i}]`, v);
  }
  // Recurse into the schema's own subschema-bearing keywords only, so we don't rescan enum strings.
  for (const key of ['properties', 'patternProperties', 'definitions', '$defs'] as const) {
    const v = obj[key];
    if (v && typeof v === 'object') for (const [name, sub] of Object.entries(v)) schemaSpans(sub, `${base}.${key}.${name}`, spans, depth + 1);
  }
  for (const key of ['items', 'additionalProperties', 'contains', 'if', 'then', 'else', 'not', 'propertyNames'] as const) {
    if (obj[key] && typeof obj[key] === 'object') schemaSpans(obj[key], `${base}.${key}`, spans, depth + 1);
  }
  for (const key of ['allOf', 'anyOf', 'oneOf', 'prefixItems'] as const) {
    if (Array.isArray(obj[key])) (obj[key] as unknown[]).forEach((s, i) => { schemaSpans(s, `${base}.${key}[${i}]`, spans, depth + 1); });
  }
}

function push(spans: TextSpan[], where: string, text: unknown): void {
  if (typeof text === 'string' && text.length > 0 && spans.length < MAX_SPANS) spans.push({ where, text });
}
