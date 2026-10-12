import type { Label } from './labels.js';
import { extractIdentifiers, fold, leaves, normalize, type IdentifierKind } from './text.js';

/** One piece of content that entered the model's context. */
export interface OutputRef {
  id: string;
  seq: number;
  server: string;
  /** Exposed name (tool/prompt) or resource URI. */
  source: string;
  kind: 'tool' | 'resource' | 'prompt';
  label: Label;
}

export type Matcher = 'exact' | 'normalized';

/** Layer-2 evidence that an argument value came from an earlier output. */
export interface Evidence {
  argPath: string;
  output: OutputRef;
  /** `identifier:<kind>`: a high-entropy identifier reproduced in the argument; `copy`: the argument
   *  value occurs verbatim (after normalization) in the output text. */
  kind: `identifier:${IdentifierKind}` | 'copy';
  matcher: Matcher;
  /** Detector rule when the identifier is a secret. */
  rule?: string;
}

export interface EvictionNotice {
  output: OutputRef;
  bytes: number;
}

interface TierA {
  ref: OutputRef;
  raw: string;
  norm: string;
  bytes: number;
}

interface TierBEntry {
  kind: IdentifierKind;
  rule?: string;
  outputs: OutputRef[];
}

/** Minimum length of an argument value for a whole-value `copy` match; shorter values are too common. */
const MIN_COPY_LEN = 16;

/**
 * Per-session provenance index (DESIGN.md §2, "Bounded memory and eviction").
 *
 * Tier A keeps full text (normalized) for copy matching, FIFO under a byte budget. Tier B keeps only
 * SHA-256 hashes of identifiers, so it is small, survives Tier-A eviction, and never retains a secret
 * in plaintext. Eviction is reported to the caller, which logs it and marks later decisions degraded;
 * Layer-1 labels are unaffected because the context label is a running join.
 */
export class ProvenanceIndex {
  private readonly tierA: TierA[] = [];
  private tierABytes = 0;
  private readonly tierB = new Map<string, TierBEntry>();
  private tierBCount = 0;
  private readonly maxTierABytes: number;
  private readonly maxTierBEntries: number;
  /** Outputs whose full text is gone; their identifiers may also be gone if Tier B overflowed. */
  evicted: OutputRef[] = [];

  constructor(opts: { maxTierABytes: number; maxTierBEntries?: number }) {
    this.maxTierABytes = opts.maxTierABytes;
    this.maxTierBEntries = opts.maxTierBEntries ?? 200_000;
  }

  /** Indexes an output's texts; returns the identifiers found and any evictions this caused. */
  add(ref: OutputRef, texts: string[]): { secrets: string[]; identifiers: number; evictions: EvictionNotice[] } {
    const raw = texts.join('\n');
    const norm = normalize(raw);
    const secrets = new Set<string>();
    let identifiers = 0;
    for (const id of extractIdentifiers(raw)) {
      identifiers++;
      if (id.kind === 'secret' && id.rule) secrets.add(id.rule);
      for (const h of new Set([`r:${id.rawHash}`, `n:${id.normHash}`])) {
        const entry = this.tierB.get(h);
        if (entry) {
          if (!entry.outputs.some((o) => o.id === ref.id)) entry.outputs.push(ref);
        } else if (this.tierBCount < this.maxTierBEntries) {
          this.tierB.set(h, { kind: id.kind, ...(id.rule ? { rule: id.rule } : {}), outputs: [ref] });
          this.tierBCount++;
        }
      }
    }
    const bytes = raw.length + norm.length;
    this.tierA.push({ ref, raw, norm, bytes });
    this.tierABytes += bytes;
    const evictions: EvictionNotice[] = [];
    while (this.tierABytes > this.maxTierABytes && this.tierA.length > 0) {
      const e = this.tierA.shift();
      if (!e) break;
      this.tierABytes -= e.bytes;
      this.evicted.push(e.ref);
      evictions.push({ output: e.ref, bytes: e.bytes });
    }
    return { secrets: [...secrets], identifiers, evictions };
  }

  /** Attributes each string leaf of `args` to earlier outputs. */
  attribute(args: unknown): Evidence[] {
    const out: Evidence[] = [];
    const seen = new Set<string>();
    const push = (e: Evidence): void => {
      const key = `${e.argPath}|${e.output.id}|${e.kind}`;
      if (!seen.has(key)) {
        seen.add(key);
        out.push(e);
      }
    };
    for (const leaf of leaves(args)) {
      // Tier B: identifiers reproduced in the argument. Extraction runs on the raw value, on its folded
      // form (zero-width / fullwidth disguises removed, case kept for case-sensitive detectors) and on
      // its normalized form; only a raw-hash hit on the raw value counts as an exact match.
      const passes: [string, boolean][] = [[leaf.value, true], [fold(leaf.value), false], [normalize(leaf.value), false]];
      for (const [variant, isRaw] of passes) for (const id of extractIdentifiers(variant)) {
        const exact = isRaw ? this.tierB.get(`r:${id.rawHash}`) : undefined;
        const hit = exact ?? this.tierB.get(`n:${id.normHash}`);
        if (!hit) continue;
        for (const o of hit.outputs) {
          push({ argPath: leaf.path, output: o, kind: `identifier:${hit.kind}`, matcher: exact ? 'exact' : 'normalized', ...(hit.rule ? { rule: hit.rule } : {}) });
        }
      }
      // Tier A: verbatim copy of a long-enough value.
      const n = normalize(leaf.value);
      if (n.length < MIN_COPY_LEN) continue;
      for (const a of this.tierA) {
        if (a.raw.includes(leaf.value)) push({ argPath: leaf.path, output: a.ref, kind: 'copy', matcher: 'exact' });
        else if (a.norm.includes(n)) push({ argPath: leaf.path, output: a.ref, kind: 'copy', matcher: 'normalized' });
      }
    }
    return out;
  }

  get stats(): { tierABytes: number; tierAOutputs: number; tierBEntries: number; evicted: number } {
    return { tierABytes: this.tierABytes, tierAOutputs: this.tierA.length, tierBEntries: this.tierBCount, evicted: this.evicted.length };
  }
}
