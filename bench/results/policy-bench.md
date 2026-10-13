Policy worst-case evaluation — Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz, Node v22.19.0

Policy deadline: 50 ms over the whole evaluation. Columns: p50 / p95 / max.

| case | whole decision (attribution + policy) | policy evaluation alone | denied by deadline |
|---|---|---|---|
| small args | 0.74 / 1.50 / 38.25 ms | 0.14 / 0.37 / 7.41 ms | 0/5000 |
| 128 KB body | 65.45 / 77.47 / 100.86 ms | 15.93 / 20.94 / 26.45 ms | 0/300 |
| deeply nested args | 12.03 / 18.39 / 42.26 ms | 0.16 / 0.35 / 2.57 ms | 0/500 |
| many keys (4000, under the field cap) | 56.06 / 72.60 / 147.37 ms | 23.02 / 31.37 / 50.37 ms | 0/500 |
| too many keys (5000, expect fast deny) | 42.15 / 78.87 / 185.02 ms | 7.66 / 14.72 / 23.48 ms | 0/500 |
| over-budget body (expect fast deny) | 32.24 / 40.84 / 42.44 ms | 0.01 / 0.03 / 0.09 ms | 0/200 |

The over-budget case denies immediately on the size check (note #2); no rule runs on it.
