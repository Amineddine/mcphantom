# Phase 1 latency: tools/call round trip, direct vs. via MCPhantom

Measured 2026-10-12T02:09:33.107Z on Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz (8 logical cores, 16 GB), Windows_NT 10.0.26200 x64, Node v22.19.0.
Gateway = built CLI as a separate stdio process, default config (payloads: redacted (default)). Warmup 100 calls, then sequential calls.

| payload | n | direct p50 | gateway p50 | Δ p50 | direct p95 | gateway p95 | Δ p95 | direct p99 | gateway p99 |
|---|---|---|---|---|---|---|---|---|---|
| 1 KB | 2000 | 1.83 ms | 4.56 ms | +2.73 ms | 3.66 ms | 7.80 ms | +4.14 ms | 5.11 ms | 13.18 ms |
| 64 KB | 500 | 4.87 ms | 15.88 ms | +11.02 ms | 8.32 ms | 23.28 ms | +14.96 ms | 14.23 ms | 82.97 ms |
| 1 MB | 60 | 46.68 ms | 83.53 ms | +36.85 ms | 83.97 ms | 112.95 ms | +28.98 ms | 88.91 ms | 120.97 ms |

The gateway adds one extra stdio hop (JSON parse + serialize on each side), routing, and a synchronous
SQLite write with redaction of up to 128 KiB of payload. No taint tracking or policy evaluation exists yet
(Phase 2+); those costs will be measured separately.
## Run-to-run variance (same machine, same day)

This laptop (i5-8250U, Windows 11, power-managed) is noisy. Three runs of the same benchmark gave these
p50 overheads; the table above is the last run, on the final Phase 1 code:

| payload | run 1 Δ p50 | run 2 Δ p50 (payloads: none) | run 3 Δ p50 (final) |
|---|---|---|---|
| 1 KB | +1.61 ms | +0.45 ms | +2.73 ms |
| 64 KB | +3.98 ms | +2.57 ms | +11.02 ms |
| 1 MB | +36.58 ms | +36.86 ms | +36.85 ms |

Readings: (1) at 1 MB the overhead is stable at ~37 ms whether or not payloads are logged, so it is
dominated by the extra hop (the SDK parses and schema-validates each message on both sides of the
gateway), not by redaction or SQLite; (2) small-payload overhead is low single-digit milliseconds but its
exact value is within this machine's noise. A single run per configuration is not statistically robust;
Phase 7 replaces this with repeated runs, confidence intervals, and a quiet Linux CI runner.
