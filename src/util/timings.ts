import { performance } from 'node:perf_hooks';

/**
 * Internal stage timing for `bench:perf` (Phase 7 item 5): how one `tools/call`'s cost splits across the
 * gateway's stages. It is not part of the configuration and the CLI never passes a sink
 * (`test/timing-hook.test.ts`); without one, the timed code paths make no extra clock reads.
 */
export type TimingStage =
  | 'resolve' | 'decide' | 'audit.decision' | 'sent' | 'upstream' | 'ingest' | 'audit.ingest' | 'audit.request'
  /** The whole handler, from its first line to the request event written. */
  | 'handler'
  /** Inside each store write: payload redaction and serialisation, then the SQLite insert. */
  | 'redact' | 'store.write';

/** Receives each stage's start and end, `performance.now()` milliseconds. */
export type TimingSink = (stage: TimingStage, start: number, end: number) => void;

/** Consecutive stages of one handler: each `lap` ends the previous stage and starts the next. */
export class StageClock {
  private readonly start = performance.now();
  private last = this.start;
  constructor(private readonly sink: TimingSink) {}

  lap(stage: TimingStage): void {
    const now = performance.now();
    this.sink(stage, this.last, now);
    this.last = now;
  }

  end(): void {
    this.sink('handler', this.start, performance.now());
  }
}
