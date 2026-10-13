Policy worst-case evaluation — Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz, Node v22.19.0

Policy deadline: 50 ms over the whole evaluation. Columns: p50 / p95 / max.

| case | whole decision (attribution + policy) | policy evaluation alone | denied by deadline |
|---|---|---|---|
| small args | 0.35 / 0.73 / 15.37 ms | 0.06 / 0.16 / 5.02 ms | 0/5000 |
| 128 KB body | 28.94 / 44.18 / 54.61 ms | 2.13 / 3.68 / 4.20 ms | 0/300 |
| deeply nested args | 6.99 / 10.98 / 15.67 ms | 0.10 / 0.23 / 3.76 ms | 0/500 |
| many keys (4000, under the field cap) | 58.43 / 69.12 / 89.81 ms | 21.92 / 27.46 / 40.01 ms | 0/500 |
| too many keys (5000, expect fast deny) | 45.73 / 52.55 / 68.48 ms | 7.60 / 10.84 / 15.42 ms | 0/500 |
| over-budget body (expect fast deny) | 13.90 / 16.10 / 23.71 ms | 0.01 / 0.03 / 0.08 ms | 0/200 |

The over-budget case denies immediately on the size check (note #2); no rule runs on it.
