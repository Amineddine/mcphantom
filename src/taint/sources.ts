import type { Label } from './labels.js';
import type { OutputRef } from './provenance.js';

/** Distinct source names kept per label, and characters kept per name (a resource URI can be long). */
export const MAX_SOURCE_NAMES = 16;
export const MAX_SOURCE_NAME_CHARS = 256;

/** The outputs of one label (untrusted, or secret) a session has seen, summarised in bounded space. */
export interface SourceSet {
  /** Outputs with this label so far. */
  count: number;
  /** Distinct source names, in first-seen order, at most {@link MAX_SOURCE_NAMES}. */
  names: string[];
  /** Outputs from sources not in `names` (the name list was full). */
  others: number;
}

/**
 * The Layer-1 explanation a decision carries, bounded whatever the session's length.
 *
 * `firstUntrusted` / `firstInternal` / `firstSecret` name the outputs that drove the context label: the first output that made it untrusted, the
 * first that made it internal, the first that made it secret. The label is a running join, so those outputs
 * are its cause; later outputs with the same label change nothing. Layer-2 rules (`may_receive`, `from()`)
 * name their sources through the decision's `evidence`. (Field names avoid the redactor's sensitive keys:
 * a key named `secret` is blanked in the log.)
 *
 * The full list is not repeated in every decision: each output is logged once, as its `taint` event, when it
 * enters the context. `through` is the last output id at decision time, so the session's `taint` events up to
 * it are exactly the outputs behind this decision (`mcphantom trace` rebuilds the list from them).
 */
export interface SessionSources {
  firstUntrusted?: OutputRef;
  firstInternal?: OutputRef;
  firstSecret?: OutputRef;
  untrustedOutputs: SourceSet;
  secretOutputs: SourceSet;
  through?: string;
}

type Raised = 'firstUntrusted' | 'firstInternal' | 'firstSecret';
const RAISE: [Raised, (before: Label, after: Label) => boolean][] = [
  ['firstUntrusted', (b, a) => b.integrity !== 'untrusted' && a.integrity === 'untrusted'],
  ['firstInternal', (b, a) => b.confidentiality === 'public' && a.confidentiality !== 'public'],
  ['firstSecret', (b, a) => b.confidentiality !== 'secret' && a.confidentiality === 'secret'],
];

const emptySet = (): SourceSet => ({ count: 0, names: [], others: 0 });
const refBytes = (r: OutputRef) => 2 * (r.id.length + r.server.length + r.source.length) + 96;

/** Keeps a session's {@link SessionSources}; its size is bounded and reported for the index budget. */
export class SourceLog {
  private readonly raisedBy: Partial<Record<Raised, OutputRef>> = {};
  private readonly untrusted = emptySet();
  private readonly secret = emptySet();
  private through: string | undefined;
  private bytesUsed = 0;

  /** Records an output entering the context, with the context label before and after it. */
  add(ref: OutputRef, before: Label, after: Label): void {
    this.through = ref.id;
    for (const [level, raised] of RAISE) {
      if (raised(before, after) && !this.raisedBy[level]) {
        const kept = { ...ref, label: { ...ref.label }, source: ref.source.slice(0, MAX_SOURCE_NAME_CHARS) };
        this.raisedBy[level] = kept;
        this.bytesUsed += refBytes(kept);
      }
    }
    if (ref.label.integrity === 'untrusted') this.note(this.untrusted, ref.source);
    if (ref.label.confidentiality === 'secret') this.note(this.secret, ref.source);
  }

  private note(set: SourceSet, source: string): void {
    set.count++;
    const name = source.slice(0, MAX_SOURCE_NAME_CHARS);
    if (set.names.includes(name)) return;
    if (set.names.length < MAX_SOURCE_NAMES) {
      set.names.push(name);
      this.bytesUsed += 2 * name.length + 32;
    } else set.others++;
  }

  /** A copy for one decision. */
  snapshot(): SessionSources {
    const copy = (s: SourceSet): SourceSet => ({ count: s.count, names: [...s.names], others: s.others });
    return { ...this.raisedBy, untrustedOutputs: copy(this.untrusted), secretOutputs: copy(this.secret), ...(this.through ? { through: this.through } : {}) };
  }

  /** Approximate bytes held, charged against the provenance index budget. */
  get bytes(): number {
    return this.bytesUsed;
  }

}

/** "a, b, c and 4 more" over a source set, for decision reasons (as before the bound: distinct names). */
export function describeSources(s: SourceSet): string {
  const shown = s.names.slice(0, 3).join(', ');
  if (s.names.length <= 3) return shown;
  // `others` > 0 only once the name list is full: more distinct names exist than were kept.
  return `${shown} and ${String(s.names.length - 3)}${s.others > 0 ? '+' : ''} more`;
}
