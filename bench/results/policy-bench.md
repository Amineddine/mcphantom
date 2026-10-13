Policy worst-case evaluation — Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz, Node v22.19.0

Policy deadline: 50 ms over the whole evaluation. Columns: p50 / p95 / max.

| case | whole decision (attribution + policy) | policy evaluation alone | denied by deadline |
|---|---|---|---|
| small args | 1.64 / 3.17 / 35.59 ms | 0.19 / 0.49 / 5.86 ms | 0/5000 |
| 128 KB body | 86.31 / 99.13 / 143.98 ms | 17.84 / 23.56 / 29.61 ms | 0/300 |
| deeply nested args | 16.52 / 21.46 / 32.60 ms | 0.18 / 0.36 / 2.54 ms | 0/500 |
| many keys (4000, under the field cap) | 57.83 / 67.83 / 91.34 ms | 22.80 / 28.20 / 43.07 ms | 0/500 |
| too many keys (5000, expect fast deny) | 43.97 / 52.02 / 68.88 ms | 7.69 / 10.63 / 15.80 ms | 0/500 |
| over-budget body (expect fast deny) | 50.18 / 62.39 / 72.57 ms | 0.01 / 0.03 / 0.15 ms | 0/200 |

The over-budget case denies immediately on the size check (note #2); no rule runs on it.
