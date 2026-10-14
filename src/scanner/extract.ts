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
 * Turns an identifier into words so phrase detectors can read it: `contents_of_the_users_ssh_key`,
 * `contentsOfTheUsersSshKey` and `contents-of-the-users-ssh-key` all become
 * "contents of the users ssh key". Returns undefined for a plain single word (nothing to add).
 */
export function humanize(name: string): string | undefined {
  const words = name.replace(/([a-z0-9])([A-Z])/g, '$1 $2').split(/[_\-.\s]+/).filter(Boolean);
  return words.length >= 2 ? words.join(' ').toLowerCase() : undefined;
}

/** A schema keyword we know: its value is structure, not text for the model. */
const SCHEMA_KEYWORDS = new Set([
  'type', 'format', 'pattern', 'minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum', 'multipleOf',
  'minLength', 'maxLength', 'minItems', 'maxItems', 'uniqueItems', 'minProperties', 'maxProperties',
  'contentEncoding', 'contentMediaType', 'readOnly', 'writeOnly', 'deprecated', 'nullable',
  '$schema', '$id', '$ref', '$anchor', '$dynamicRef', '$dynamicAnchor', '$vocabulary',
  'description', 'title', '$comment', 'const', 'default', 'enum', 'examples', 'required', 'dependentRequired',
  'properties', 'patternProperties', 'definitions', '$defs', 'dependentSchemas',
  'items', 'additionalProperties', 'unevaluatedProperties', 'unevaluatedItems', 'contains', 'if', 'then',
  'else', 'not', 'propertyNames', 'allOf', 'anyOf', 'oneOf', 'prefixItems',
]);

/** Every string inside a JSON value (keys of nested objects included), for non-string defaults etc. */
function deepStrings(v: unknown, base: string, spans: TextSpan[], depth: number): void {
  if (depth > MAX_DEPTH || spans.length >= MAX_SPANS) return;
  if (typeof v === 'string') push(spans, base, v);
  else if (Array.isArray(v)) v.forEach((x, i) => { deepStrings(x, `${base}[${i}]`, spans, depth + 1); });
  else if (v && typeof v === 'object') {
    for (const [k, x] of Object.entries(v)) {
      pushName(spans, `${base}.${k}(key)`, k);
      deepStrings(x, `${base}.${k}`, spans, depth + 1);
    }
  }
}

/** An identifier the model reads (parameter name, `required` entry, unknown keyword): raw and as words. */
function pushName(spans: TextSpan[], where: string, name: string): void {
  push(spans, where, name);
  const words = humanize(name);
  if (words) push(spans, `${where}(words)`, words);
}

/**
 * Pulls every model-visible string out of a JSON Schema. The model sees the whole schema, so a payload
 * can sit anywhere in it (full-schema poisoning): `description`, `title`, `$comment`, enum values,
 * `const`, `default`, `examples` (strings nested inside non-string values too), parameter names,
 * `required` entries, and any keyword this list does not know, with its value. Structural keywords
 * (`type`, `format`, numbers) carry no text and are skipped.
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
  for (const key of ['const', 'default', 'enum', 'examples'] as const) {
    if (obj[key] !== undefined) deepStrings(obj[key], `${base}.${key}`, spans, depth + 1);
  }
  if (Array.isArray(obj.required)) for (const [i, v] of obj.required.entries()) if (typeof v === 'string') pushName(spans, `${base}.required[${i}]`, v);
  for (const [k, v] of Object.entries(obj)) {
    if (SCHEMA_KEYWORDS.has(k)) continue;
    pushName(spans, `${base}.${k}(keyword)`, k);
    deepStrings(v, `${base}.${k}(keyword)`, spans, depth + 1);
  }
  // Recurse into the schema's own subschema-bearing keywords only, so we don't rescan enum strings.
  for (const key of ['properties', 'patternProperties', 'definitions', '$defs', 'dependentSchemas'] as const) {
    const v = obj[key];
    if (v && typeof v === 'object') {
      for (const [name, sub] of Object.entries(v)) {
        if (key === 'properties') pushName(spans, `${base}.properties.${name}(name)`, name);
        schemaSpans(sub, `${base}.${key}.${name}`, spans, depth + 1);
      }
    }
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
