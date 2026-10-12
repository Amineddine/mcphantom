import type { Prompt, Tool } from '@modelcontextprotocol/sdk/types.js';
import { fingerprint } from './canonical.js';
import type { LockfileData, ServerPins } from './lockfile.js';

export type PinStatus =
  | 'unpinned' // no lockfile at all; nothing is pinned yet
  | 'match' // fingerprint equals the pin
  | 'changed' // pin exists but fingerprint differs — a rug-pull
  | 'new'; // lockfile exists for this server but this item was not in it

export interface PinResult {
  status: PinStatus;
  fingerprint: string;
  pinned: string | undefined;
}

/**
 * Compares live definitions against the approved pins. A fingerprint is the SHA-256 of the canonical
 * JSON of the *model-visible* definition — the name, description and schemas — so a cosmetic re-ordering
 * of JSON keys does not read as a change, but any edit to what the model sees does.
 *
 * `locked` is false when there is no lockfile (or it could not be verified): then everything is
 * `unpinned` and the gateway does not block on rug-pull grounds, it only records.
 */
export class RugpullChecker {
  private readonly locked: boolean;
  private readonly servers: Record<string, ServerPins>;

  constructor(data: LockfileData | undefined, locked: boolean) {
    this.locked = locked;
    this.servers = data?.servers ?? {};
  }

  get enforcing(): boolean {
    return this.locked;
  }

  checkTool(serverId: string, tool: Tool): PinResult {
    return this.check(serverId, 'tools', tool.name, definitionOf(tool));
  }

  checkPrompt(serverId: string, prompt: Prompt): PinResult {
    return this.check(serverId, 'prompts', prompt.name, promptDefinitionOf(prompt));
  }

  checkInstructions(serverId: string, instructions: string | undefined): PinResult {
    const fp = fingerprint(instructions ?? null);
    if (!this.locked) return { status: 'unpinned', fingerprint: fp, pinned: undefined };
    const pins = this.servers[serverId];
    const pinned = pins?.instructions ?? undefined;
    if (pins === undefined || pinned === undefined) return { status: 'new', fingerprint: fp, pinned: undefined };
    return { status: pinned === fp ? 'match' : 'changed', fingerprint: fp, pinned };
  }

  private check(serverId: string, kind: 'tools' | 'prompts', name: string, def: unknown): PinResult {
    const fp = fingerprint(def);
    if (!this.locked) return { status: 'unpinned', fingerprint: fp, pinned: undefined };
    const pins = this.servers[serverId];
    const pinned = pins?.[kind][name];
    if (pins === undefined || pinned === undefined) return { status: 'new', fingerprint: fp, pinned: undefined };
    return { status: pinned === fp ? 'match' : 'changed', fingerprint: fp, pinned };
  }
}

/** The subset of a Tool that the model sees and that a rug-pull would alter. */
export function definitionOf(tool: Tool): unknown {
  return {
    name: tool.name,
    title: tool.title ?? null,
    description: tool.description ?? null,
    inputSchema: tool.inputSchema,
    outputSchema: tool.outputSchema ?? null,
    annotations: tool.annotations ?? null,
  };
}

export function promptDefinitionOf(prompt: Prompt): unknown {
  return {
    name: prompt.name,
    title: prompt.title ?? null,
    description: prompt.description ?? null,
    arguments: (prompt.arguments ?? []).map((a) => ({ name: a.name, description: a.description ?? null, required: a.required ?? false })),
  };
}

/** Builds a fresh set of pins from the current live definitions (used by `mcphantom approve`). */
export function pinsFrom(tools: Record<string, Tool[]>, prompts: Record<string, Prompt[]>, instructions: Record<string, string | undefined>): LockfileData {
  const servers: Record<string, ServerPins> = {};
  const now = new Date().toISOString();
  const ids = new Set([...Object.keys(tools), ...Object.keys(prompts), ...Object.keys(instructions)]);
  for (const id of [...ids].sort()) {
    const t: Record<string, string> = {};
    for (const tool of tools[id] ?? []) t[tool.name] = fingerprint(definitionOf(tool));
    const p: Record<string, string> = {};
    for (const prompt of prompts[id] ?? []) p[prompt.name] = fingerprint(promptDefinitionOf(prompt));
    servers[id] = { instructions: id in instructions ? fingerprint(instructions[id] ?? null) : null, tools: t, prompts: p, approvedAt: now };
  }
  return { version: 1, servers };
}
