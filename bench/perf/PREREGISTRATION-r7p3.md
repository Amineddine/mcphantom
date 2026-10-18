# Pre-registration — the R7p-3 fix: eviction rerun

Committed and pushed **before** the rerun below runs on the fixed code. Owner decisions: 2026-10-17 and
2026-10-18 in [`docs/decisions.md`](../../docs/decisions.md). Finding R7p-3 and the "before" numbers are in
[`docs/reviews/phase-7-perf.md`](../../docs/reviews/phase-7-perf.md) and
[`bench/results/eviction.md`](../results/eviction.md). The predictions below are locked by this commit.
Anything changed after it is an amendment, dated and listed at the end, never a silent edit.

## What changed (the fix under test)

1. **Tier B shares the byte budget.** Each entry is charged 288 bytes and each further output on an entry 40
   bytes: the V8 heap cost measured on Node 22 (≈ 280 B and ≈ 34 B), rounded up. These are charged against
   `taint.max_index_mb`, together with Tier A and the source summary. The 200,000-entry cap is gone. (It held
   ≈ 56 MB that the budget never saw.)
2. **Eviction order.** Over the budget, Tier A evicts oldest first, as before. Only when Tier A is empty does
   Tier B evict its oldest entries. An identifier seen again in a newer output moves to the newest end.
3. **Every Tier B eviction is reported and marks the session degraded,** as a Tier A eviction does. The
   engine also records the integrity level of every output it lost track of (Tier A or Tier B eviction, or
   partial decoding), labelled or not.
4. **Deny-side `from()` fails closed.** In a deny or ask rule, `from(v, level)` with no match is an error
   instead of `false` in two cases: the session lost track of an output of that `level`, or attribution
   could not check `v` in full. The error is a policy error, so the call is denied, with a reason that
   names the bound and the way out. Negated uses fail closed the same way. CEL still evaluates
   `false && error` as false. Allow rules and declassify conditions are unchanged.
5. **R7p-2 (same PR).** A decision records at most 4 evidence entries per argument path and 32 in all. The
   strongest are kept: higher confidentiality, then untrusted, then the stronger matcher, then the newer
   output. The entry a `may_receive` deny cites is always kept, and a count of the omitted entries is
   recorded. The verdict is still reached on all the evidence.

## What runs

- **E only** (`bench:perf -- --parts eviction`), on the same commit, unchanged:
  - the item-5 harness, arms F1/F2/F3, budgets 32 / 4 / 1 / 0.25 / 0.0625 MiB;
  - the item-3 suite (83 traces) and the policy family (8 traces).
- **Policy family:** on the laptop (`--sets policy --out-dir perf-r7p3`), once.
- **Suite:** once on CI, through `perf.yml` with `jobs: eviction`, `out_dir: perf-r7p3`, in 8 shards (owner
  decision 2026-10-18). Only the eviction job runs.
- **Report:** `bench/perf/report-eviction.mts` writes `bench/results/eviction-r7p3.md`, with a before → after
  table against the item-5 rows. `bench/results/perf/` and `bench/results/eviction.md` stay as they are.
- **Run once.** A CI job that fails for an infrastructure reason may be re-run once; that is recorded as an
  amendment. `--smoke` runs are never reported.

## Predictions

| id | prediction |
|---|---|
| Q-1 | **Policy family, claimed attacks: 0 / 5 succeed in every arm and at every budget** (item 5: 4 / 5 under F3). Cause: under F3 the attacker's recipient or URL is indexed after the flood, so it is the newest Tier B entry and survives. The four `from()` attacks are therefore denied **on evidence**, not fail-closed. `pol-declassify-attack` is stopped by its policy rule again, not by the trifecta check. |
| Q-2 | **Policy family, partial leaks: 0 / 5 in every cell.** |
| Q-3 | **Policy family, false blocks (the cost): 2 / 2** wherever an untrusted output is evicted: **F1 at 1, 0.25 and 0.0625 MiB, and F2 and F3 at every budget.** `pol-recipient-trusted` and `pol-declassify-benign` are both denied fail-closed by the deny-side `from(arg.to, "untrusted")` rule. In item 5, F1 and F2 had 0 / 2 and F3 had 1 / 2. **F0, and F1 at 32 and 4 MiB, stay 0 / 2.** |
| Q-4 | **Policy family, fail-closed traces:** 3 in each cell of Q-3 (the two benign traces and `out-pol-recipient-spelled-out`); 0 elsewhere. No claimed attack trace has a fail-closed deny. |
| Q-5 | **Outside the claims:** `out-pol-recipient-spelled-out` goes 1 / 1 → **0 / 1** in the Q-3 cells (denied fail-closed). This is a side effect of failing closed, not a new claim. F0, and F1 at 32 and 4 MiB, stay 1 / 1. |
| Q-6 | **Suite: attack success 0 / 60, partial leaks and false blocks unchanged from item 5 in every cell.** The suite has no policy rules, so only items 1–3 of the fix can reach it. Fail-closed counts under F3 may fall, never rise: evidence is now found before the fail-closed checks run. Outside the claims: unchanged. |
| Q-7 | **Tier B evictions:** every F3 trace in both sets, at every budget. The flood is ≈ 222k entries ≈ 64 MB, over even 32 MiB. No F0, F1 or F2 trace has any. |
| Q-8 | **Index bound:** in every trace, Tier A + Tier B + external bytes ≤ the budget after every ingest. This is checked in the harness, not just at the end. |
| Q-9 | **M1 (index size at the end of each trace, F0):** Tier A and Tier B entry counts unchanged from item 5. Tier B bytes reported for the first time. |

## Not measured here

- Latency (L, B, D) and long-session memory (M2) of the fix. The fix adds work on ingest only when an
  identifier repeats (a map delete + set), and adds no work at decision time except for `from()` with no
  match. The latency numbers from item 5 stand. Any change would be measured in its own PR.
- A Tier B flood sent **after** the recipient, followed by an attack. `test/tierb-budget.test.ts` covers it
  at the decision level (fail-closed deny); the harness has no such arm.
- The allow-side hole (a `!from()` in an allow rule or declassify condition in a degraded session). It is
  the next PR (owner decision 2026-10-18).

## Amendments

1. **2026-10-18, after the CI run and before the laptop run finished: CI also ran the policy family.**
   - `perf.yml` does not pass `--sets`, so the 8 eviction shards (run
     [39088191904](https://github.com/Amineddine/mcphantom/actions/runs/39088191904) on `5224d09`) used the
     default, `suite,policy`. The laptop run of the policy family went ahead as registered.
   - Replay is deterministic, so the two must agree. The report uses the CI rows (the first files read), and the
     review checks that the laptop's rows are identical, trace by trace.
   - No prediction changed.
2. **2026-10-18, report only (no rerun).** After the run, two report changes:
   - `report-eviction.mts` gained the Tier B bytes table that Q-9 promised but the harness had not printed. The
     raw rows already held `tierBBytes`.
   - The Q-8 section shows counts and the largest excess per cell instead of naming every trace.
