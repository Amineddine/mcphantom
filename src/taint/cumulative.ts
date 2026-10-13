/**
 * Per-sink reassembly buffers for the Layer-2 `cumulative` matcher (DESIGN.md §2): an exfiltration
 * split across several calls to the same tool ("send the first 8 characters, then the rest") only forms
 * the identifier when the pieces are put back together.
 *
 * A buffer holds, in order, the string arguments of calls that were actually forwarded to one sink (a
 * denied call sent nothing). It is bounded by characters per sink, by a time window, and by the number
 * of sinks (least recently used dropped first). Trimming or dropping is reported so decisions can be
 * marked degraded; it never affects Layer 1.
 */
export const MAX_SINK_CHARS = 16 * 1024;
export const SINK_WINDOW_MS = 15 * 60 * 1000;
export const MAX_SINKS = 256;

interface Piece {
  at: number;
  text: string;
}

export class SinkBuffers {
  private readonly sinks = new Map<string, Piece[]>();
  /** Sinks whose buffer lost content to a bound (not to the time window, which is policy). */
  private readonly trimmed = new Set<string>();

  /** Appends what was sent to `sink`. */
  record(sink: string, text: string, now: number): void {
    if (text.length === 0) return;
    const pieces = this.sinks.get(sink) ?? [];
    this.sinks.delete(sink); // re-insert: Map order is the LRU order
    pieces.push({ at: now, text: text.length > MAX_SINK_CHARS ? text.slice(-MAX_SINK_CHARS) : text });
    if (text.length > MAX_SINK_CHARS) this.trimmed.add(sink);
    let total = pieces.reduce((n, p) => n + p.text.length, 0);
    while (total > MAX_SINK_CHARS && pieces.length > 1) {
      total -= (pieces.shift() as Piece).text.length;
      this.trimmed.add(sink);
    }
    this.sinks.set(sink, pieces);
    while (this.sinks.size > MAX_SINKS) {
      const oldest = this.sinks.keys().next().value as string;
      this.sinks.delete(oldest);
      this.trimmed.add(oldest);
    }
  }

  /** What was sent to `sink` within the window, oldest first, plus whether a bound dropped content. */
  prior(sink: string, now: number): { text: string; calls: number; trimmed: boolean } {
    const pieces = (this.sinks.get(sink) ?? []).filter((p) => now - p.at <= SINK_WINDOW_MS);
    return { text: pieces.map((p) => p.text).join(''), calls: pieces.length, trimmed: this.trimmed.has(sink) };
  }

  get stats(): { sinks: number; chars: number } {
    let chars = 0;
    for (const ps of this.sinks.values()) for (const p of ps) chars += p.text.length;
    return { sinks: this.sinks.size, chars };
  }
}

/** The string leaves of one call, concatenated in order with no separator (how split pieces rejoin). */
export function joinedLeaves(values: readonly string[]): string {
  return values.join('');
}
