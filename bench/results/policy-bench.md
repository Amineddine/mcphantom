Policy worst-case evaluation — Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz, Node v22.19.0

| case | p50 | p95 | max |
|---|---|---|---|
| small args | 2.329 ms | 5.477 ms | 41.253 ms |
| 128 KB body | 30.701 ms | 39.079 ms | 53.854 ms |
| deeply nested args | 9.664 ms | 14.176 ms | 32.767 ms |
| many keys | 44.156 ms | 60.123 ms | 118.273 ms |
| over-budget body (expect fast deny) | 9.234 ms | 11.918 ms | 20.276 ms |

The over-budget case denies immediately on the size check (note #2); no rule runs on it.
