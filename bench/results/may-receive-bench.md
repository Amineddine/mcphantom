# `may_receive` fail-closed: false-block cost on benign calls (`npm run bench:may-receive`)

Generated 2026-10-15T03:23:40.865Z · Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz, Node v22.19.0. Every call is benign, so every deny is a false block. Server bound: `may_receive: internal`, evidence mode. Options: see the header of `bench/may-receive-bench.mts`.

| session state | literal | A (any bound) | B (implemented: hiding bounds only) | C (B, clear-text losses only) |
|---|---|---|---|---|
| internal only | 11/15 | 0/15 | 0/15 | 0/15 |
| small secret | 11/15 | 11/15 | 5/15 | 5/15 |
| large secret | 15/15 | 15/15 | 15/15 | 5/15 |

| call | session | degraded by | literal | A | B | C | decide ms |
|---|---|---|---|---|---|---|---|
| 1 KiB message | internal only | — | allow | allow | allow | allow | 6.7 |
| 4 KiB message | internal only | — | allow | allow | allow | allow | 12.3 |
| 8 KiB message | internal only | — | allow | allow | allow | allow | 14.8 |
| 16 KiB document | internal only | fuzzy | deny | allow | allow | allow | 26.8 |
| 32 KiB document | internal only | fuzzy | deny | allow | allow | allow | 38.0 |
| 63 KiB document | internal only | fuzzy | deny | allow | allow | allow | 67.2 |
| 65 KiB document | internal only | leaf-size, fuzzy | deny | allow | allow | allow | 63.5 |
| 256 KiB file write | internal only | leaf-size, fuzzy, cumulative | deny | allow | allow | allow | 91.1 |
| 100 fields of 200 B (JSON batch) | internal only | cumulative | deny | allow | allow | allow | 84.3 |
| 512 short fields | internal only | — | allow | allow | allow | allow | 75.5 |
| 513 short fields | internal only | leaves | deny | allow | allow | allow | 59.1 |
| 2000 short fields | internal only | leaves | deny | allow | allow | allow | 119.9 |
| 40 fields of 2 KiB | internal only | fuzzy, cumulative | deny | allow | allow | allow | 131.6 |
| base64 attachment 48 KiB (binary) | internal only | fuzzy, decode-limit, cumulative | deny | allow | allow | allow | 138.4 |
| small message after 10 earlier 2 KiB sends to the same tool | internal only | cumulative | deny | allow | allow | allow | 19.2 |
| 1 KiB message | small secret | — | allow | allow | allow | allow | 2.5 |
| 4 KiB message | small secret | — | allow | allow | allow | allow | 12.7 |
| 8 KiB message | small secret | — | allow | allow | allow | allow | 13.3 |
| 16 KiB document | small secret | fuzzy | deny | deny | allow | allow | 22.1 |
| 32 KiB document | small secret | fuzzy | deny | deny | allow | allow | 37.0 |
| 63 KiB document | small secret | fuzzy | deny | deny | allow | allow | 64.8 |
| 65 KiB document | small secret | leaf-size, fuzzy | deny | deny | deny | deny | 67.9 |
| 256 KiB file write | small secret | leaf-size, fuzzy, cumulative | deny | deny | deny | deny | 89.6 |
| 100 fields of 200 B (JSON batch) | small secret | cumulative | deny | deny | allow | allow | 69.9 |
| 512 short fields | small secret | — | allow | allow | allow | allow | 49.1 |
| 513 short fields | small secret | leaves | deny | deny | deny | deny | 54.7 |
| 2000 short fields | small secret | leaves | deny | deny | deny | deny | 102.3 |
| 40 fields of 2 KiB | small secret | fuzzy, cumulative | deny | deny | allow | allow | 121.9 |
| base64 attachment 48 KiB (binary) | small secret | fuzzy, decode-limit, cumulative | deny | deny | deny | deny | 98.5 |
| small message after 10 earlier 2 KiB sends to the same tool | small secret | cumulative | deny | deny | allow | allow | 15.7 |
| 1 KiB message | large secret | output-decode | deny | deny | deny | allow | 2.4 |
| 4 KiB message | large secret | output-decode | deny | deny | deny | allow | 7.2 |
| 8 KiB message | large secret | output-decode | deny | deny | deny | allow | 13.8 |
| 16 KiB document | large secret | fuzzy, output-decode | deny | deny | deny | allow | 18.8 |
| 32 KiB document | large secret | fuzzy, output-decode | deny | deny | deny | allow | 31.8 |
| 63 KiB document | large secret | fuzzy, output-decode | deny | deny | deny | allow | 57.1 |
| 65 KiB document | large secret | leaf-size, fuzzy, output-decode | deny | deny | deny | deny | 70.5 |
| 256 KiB file write | large secret | leaf-size, fuzzy, cumulative, output-decode | deny | deny | deny | deny | 104.7 |
| 100 fields of 200 B (JSON batch) | large secret | cumulative, output-decode | deny | deny | deny | allow | 79.7 |
| 512 short fields | large secret | output-decode | deny | deny | deny | allow | 45.6 |
| 513 short fields | large secret | leaves, output-decode | deny | deny | deny | deny | 45.9 |
| 2000 short fields | large secret | leaves, output-decode | deny | deny | deny | deny | 124.8 |
| 40 fields of 2 KiB | large secret | fuzzy, cumulative, output-decode | deny | deny | deny | allow | 159.6 |
| base64 attachment 48 KiB (binary) | large secret | fuzzy, decode-limit, cumulative, output-decode | deny | deny | deny | deny | 126.2 |
| small message after 10 earlier 2 KiB sends to the same tool | large secret | cumulative, output-decode | deny | deny | deny | allow | 20.1 |
