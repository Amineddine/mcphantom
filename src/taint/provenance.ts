import type { Label } from './labels.js';
import { extractIdentifiers, fold, leaves, normalize, type IdentifierKind } from './text.js';
import { decodeVariants, type DecodeLimits, type Decoder } from '../text/decode.js';
import { containment, fingerprints, reduce } from './fuzzy.js';

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

/**
 * How the argument was tied to the output: `exact`/`normalized` (verbatim, or after folding case,
 * width, invisible characters and look-alikes), `decoded` (after undoing an encoding on either side —
 * `chain`/`outputChain` say which), `fuzzy` (text copied with light edits or reordering: winnowing
 * fingerprints, `score` = fraction of the argument's fingerprints found in the output).
 */
export type Matcher = 'exact' | 'normalized' | 'decoded' | 'fuzzy';

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
  /** Decoders applied to the argument before the match (matcher `decoded`). */
  chain?: Decoder[];
  /** Decoders applied to the output before indexing, when the identifier was encoded there. */
  outputChain?: Decoder[];
  /** `fuzzy` only: fraction of the argument's fingerprints present in the output (0–1). */
  score?: number;
}

export interface Attribution {
  evidence: Evidence[];
  /** True if a bound (leaf/call size, decode budget, variant cap) stopped attribution early, so the
   *  absence of evidence is weaker than usual. */
  degraded: boolean;
}

export interface EvictionNotice {
  output: OutputRef;
  bytes: number;
}

interface TierA {
  ref: OutputRef;
  raw: string;
  norm: string;
  /** Winnowing fingerprints for the fuzzy matcher, sorted. */
  fp: Uint32Array;
  bytes: number;
}

interface TierBSource {
  ref: OutputRef;
  /** Set when the identifier was found only after decoding the output. */
  chain?: Decoder[];
}

interface TierBEntry {
  kind: IdentifierKind;
  rule?: string;
  outputs: TierBSource[];
}

/** Minimum length of an argument value for a whole-value `copy` match; shorter values are too common. */
const MIN_COPY_LEN = 16;
/** Cap on argument leaves attributed per call, so a many-field call cannot make attribution slow. */
export const MAX_ATTRIBUTED_LEAVES = 512;
/** Total characters attributed per call across all leaves. */
export const MAX_ATTRIBUTED_TOTAL = 1024 * 1024;
/** Cap on characters of a single leaf that are attributed (identifier scan + copy match). */
export const MAX_ATTRIBUTED_CHARS = 64 * 1024;

/** Fuzzy matching: a leaf needs this many reduced characters (letters/digits) to be compared — the
 *  winnowing guarantee is W + K - 1 = 27 — and a match needs both a minimum number of shared
 *  fingerprints and a minimum fraction of the leaf's fingerprints. Set from first principles and the
 *  dev split of bench:evasion; the test split is held out. */
const MIN_FUZZY_REDUCED = 40;
const FUZZY_MIN_SHARED = 3;
export const FUZZY_MIN_SCORE = 0.5;
/** Characters of one leaf, and of all leaves of a call, compared by the fuzzy matcher. */
export const MAX_FUZZY_PER_LEAF = 8 * 1024;
export const MAX_FUZZY_PER_CALL = 32 * 1024;

/** Leaves shorter than this are not decoded: no identifier we track fits in fewer characters. */
const MIN_DECODE_LEN = 8;
/** Characters of argument text run through the decoders per call (sum over leaves). */
export const MAX_DECODED_PER_CALL = 128 * 1024;
export const ARG_DECODE_LIMITS: DecodeLimits = { maxDepth: 3, maxVariants: 32, maxChars: 256 * 1024, wholeOn: 'tokens' };
/** Characters of each output run through the decoders; the rest is indexed undecoded (degraded). */
export const MAX_DECODED_PER_OUTPUT = 128 * 1024;
export const OUTPUT_DECODE_LIMITS: DecodeLimits = { maxDepth: 2, maxVariants: 16, maxChars: 512 * 1024, wholeOn: 'tokens' };
/** Encodings under which a stored secret realistically appears in an output (Kubernetes secrets are
 *  base64, configs are URL- or JSON-escaped). Only these may raise an output's label to `secret`;
 *  rot13 and reversal feed attribution only. */
const SECRET_BEARING: ReadonlySet<Decoder> = new Set(['base64', 'hex', 'url', 'html', 'escape', 'despace']);

/**
 * Per-session provenance index (DESIGN.md §2, "Bounded memory and eviction").
 *
 * Tier A keeps full text (normalized) for copy matching, FIFO under a byte budget. Tier B keeps only
 * SHA-256 hashes of identifiers — including identifiers found in decoded forms of an output — so it is
 * small, survives Tier-A eviction, and never retains a secret in plaintext. Eviction is reported to the
 * caller, which logs it and marks later decisions degraded; Layer-1 labels are unaffected because the
 * context label is a running join.
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

  /**
   * Indexes an output's texts. Returns the secret rules found (raw, or under a secret-bearing
   * encoding), the identifier count, any evictions this caused, and whether decoding was cut short.
   */
  add(ref: OutputRef, texts: string[]): { secrets: string[]; identifiers: number; evictions: EvictionNotice[]; decodeTruncated: boolean } {
    const raw = texts.join('\n');
    const norm = normalize(raw);
    const secrets = new Set<string>();
    let identifiers = 0;
    const index = (text: string, chain?: Decoder[]): void => {
      // Under rot13/reversal a random token is just another random token: indexing it would only fill
      // Tier B. Those variants contribute secrets, URLs and e-mail addresses.
      const tokens = !chain?.some((d) => d === 'rot13' || d === 'reverse');
      for (const id of extractIdentifiers(text, { tokens })) {
        identifiers++;
        if (id.kind === 'secret' && id.rule && (!chain || chain.every((d) => SECRET_BEARING.has(d)))) secrets.add(id.rule);
        for (const h of new Set([`r:${id.rawHash}`, `n:${id.normHash}`])) {
          const entry = this.tierB.get(h);
          if (entry) {
            if (!entry.outputs.some((o) => o.ref.id === ref.id)) entry.outputs.push({ ref, ...(chain ? { chain } : {}) });
          } else if (this.tierBCount < this.maxTierBEntries) {
            this.tierB.set(h, { kind: id.kind, ...(id.rule ? { rule: id.rule } : {}), outputs: [{ ref, ...(chain ? { chain } : {}) }] });
            this.tierBCount++;
          }
        }
      }
    };
    index(raw);
    // Identifiers hidden in an encoded form of the output (a base64 Kubernetes secret, a reversed URL in
    // an injected page) are indexed too, so an argument carrying them in clear text is attributed.
    const decoded = decodeVariants(raw.slice(0, MAX_DECODED_PER_OUTPUT), OUTPUT_DECODE_LIMITS);
    for (const v of decoded.variants) index(fold(v.text), v.chain);
    const decodeTruncated = decoded.truncated || raw.length > MAX_DECODED_PER_OUTPUT;

    const fp = fingerprints(norm, true);
    const bytes = raw.length + norm.length + fp.byteLength;
    this.tierA.push({ ref, raw, norm, fp, bytes });
    this.tierABytes += bytes;
    const evictions: EvictionNotice[] = [];
    while (this.tierABytes > this.maxTierABytes && this.tierA.length > 0) {
      const e = this.tierA.shift();
      if (!e) break;
      this.tierABytes -= e.bytes;
      this.evicted.push(e.ref);
      evictions.push({ output: e.ref, bytes: e.bytes });
    }
    return { secrets: [...secrets], identifiers, evictions, decodeTruncated };
  }

  /** Attributes each string leaf of `args` to earlier outputs. */
  attribute(args: unknown): Evidence[] {
    return this.attributeCall(args).evidence;
  }

  /** Attributes each string leaf of `args` to earlier outputs, reporting whether a bound was hit. */
  attributeCall(args: unknown): Attribution {
    const out: Evidence[] = [];
    const seen = new Set<string>();
    let degraded = false;
    const push = (e: Evidence): void => {
      const key = `${e.argPath}|${e.output.id}|${e.kind}`;
      if (!seen.has(key)) {
        seen.add(key);
        out.push(e);
      }
    };
    const lookup = (leafPath: string, text: string, isRaw: boolean, chain?: Decoder[]): void => {
      const tokens = !chain?.some((d) => d === 'rot13' || d === 'reverse');
      for (const id of extractIdentifiers(text, { tokens })) {
        const exact = isRaw ? this.tierB.get(`r:${id.rawHash}`) : undefined;
        const hit = exact ?? this.tierB.get(`n:${id.normHash}`);
        if (!hit) continue;
        for (const src of hit.outputs) {
          const matcher: Matcher = chain || src.chain ? 'decoded' : exact ? 'exact' : 'normalized';
          push({
            argPath: leafPath, output: src.ref, kind: `identifier:${hit.kind}`, matcher,
            ...(hit.rule ? { rule: hit.rule } : {}),
            ...(chain ? { chain } : {}),
            ...(src.chain ? { outputChain: src.chain } : {}),
          });
        }
      }
    };
    // Bound the work: attributing thousands of leaves (a hostile or pathological call) is capped so
    // one call cannot make the decision path slow. The Layer-1 context label is unaffected either way.
    const allLeaves = leaves(args);
    if (allLeaves.length > MAX_ATTRIBUTED_LEAVES) degraded = true;
    let budget = MAX_ATTRIBUTED_TOTAL;
    let decodeBudget = MAX_DECODED_PER_CALL;
    let fuzzyBudget = MAX_FUZZY_PER_CALL;
    const decodeQueue: { path: string; value: string }[] = [];
    for (const full of allLeaves.slice(0, MAX_ATTRIBUTED_LEAVES)) {
      if (budget <= 0) {
        degraded = true;
        break;
      }
      const take = Math.min(full.value.length, MAX_ATTRIBUTED_CHARS, budget);
      budget -= take;
      if (take < full.value.length) degraded = true;
      const leaf = take < full.value.length ? { path: full.path, value: full.value.slice(0, take) } : full;
      // Tier B: identifiers reproduced in the argument. Extraction runs on the raw value, on its folded
      // form (zero-width / fullwidth / look-alike disguises removed, case kept for case-sensitive
      // detectors) and on its normalized form; only a raw-hash hit on the raw value counts as exact.
      lookup(leaf.path, leaf.value, true);
      lookup(leaf.path, fold(leaf.value), false);
      lookup(leaf.path, normalize(leaf.value), false);
      // Tier A: verbatim copy of a long-enough value.
      const n = normalize(leaf.value);
      if (n.length >= MIN_COPY_LEN) {
        for (const a of this.tierA) {
          if (a.raw.includes(leaf.value)) push({ argPath: leaf.path, output: a.ref, kind: 'copy', matcher: 'exact' });
          else if (a.norm.includes(n)) push({ argPath: leaf.path, output: a.ref, kind: 'copy', matcher: 'normalized' });
        }
      }
      // Fuzzy: text copied with light edits or reordering. Runs after the exact/normalized copy check,
      // so an output already matched verbatim keeps the stronger evidence (same de-duplication key).
      if (reduce(leaf.value.slice(0, MAX_FUZZY_PER_LEAF)).length >= MIN_FUZZY_REDUCED) {
        const piece = leaf.value.slice(0, Math.min(MAX_FUZZY_PER_LEAF, fuzzyBudget));
        if (piece.length < leaf.value.length) degraded = true;
        fuzzyBudget -= piece.length;
        const needle = fingerprints(piece);
        if (needle.length > 0) {
          for (const a of this.tierA) {
            const { shared, score } = containment(needle, a.fp);
            if (shared >= FUZZY_MIN_SHARED && score >= FUZZY_MIN_SCORE) {
              push({ argPath: leaf.path, output: a.ref, kind: 'copy', matcher: 'fuzzy', score: Math.round(score * 100) / 100 });
            }
          }
        }
      }
      if (leaf.value.length >= MIN_DECODE_LEN) decodeQueue.push(leaf);
    }
    // Decoded forms of the arguments, identifiers only, after every direct match so the strongest
    // matcher is the one recorded. Decoding is the expensive part, so it has its own per-call budget.
    for (const leaf of decodeQueue) {
      if (leaf.value.length > decodeBudget) {
        degraded = true;
        break;
      }
      decodeBudget -= leaf.value.length;
      const r = decodeVariants(leaf.value, ARG_DECODE_LIMITS);
      if (r.truncated) degraded = true;
      // Folded form only: the lookup compares normalized hashes already, so a normalize pass would
      // repeat the work.
      for (const v of r.variants) lookup(leaf.path, fold(v.text), false, v.chain);
    }
    return { evidence: out, degraded };
  }

  get stats(): { tierABytes: number; tierAOutputs: number; tierBEntries: number; evicted: number } {
    return { tierABytes: this.tierABytes, tierAOutputs: this.tierA.length, tierBEntries: this.tierBCount, evicted: this.evicted.length };
  }
}
