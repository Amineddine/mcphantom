# Phase 7 item 5 — latency, memory, eviction loss: review

Branch `7/pr5-latency` (#15). Pre-registration `bench/perf/PREREGISTRATION-perf.md`, committed and pushed
(`95e762a`) before any harness existed. Amendments 1–3 were made after smoke runs and before the first real run;
no prediction changed. Run once:
- **CI:** `perf.yml` run [38995252040](https://github.com/Amineddine/mcphantom/actions/runs/38995252040) on
  commit `251b5ed` — 3 replicate VMs, plus 8 eviction shards.
- **Laptop:** the reduced set, on the same commit.

Results: [`bench/results/perf.md`](../../bench/results/perf.md) and
[`bench/results/eviction.md`](../../bench/results/eviction.md); raw data in `bench/results/perf/`.
Owner decisions: 2026-10-17 in [`docs/decisions.md`](../decisions.md).

## What was measured

- **L — round trip, direct vs through the built CLI** (echo fixture):
  - sizes 1 KiB, 64 KiB, 1 MiB and the slash-heavy 128 KiB (R6b-10);
  - each with `payloads: redacted` and `none`;
  - plus `server-filesystem` reading a 64 KiB file.
- **B — cost breakdown of one `tools/call`**, from an internal timing hook. The hook is unreachable from
  configuration and the CLI never passes it (`test/timing-hook.test.ts`); the bench entry also measures the hook's
  own overhead.
- **D — decision level, in process.**
- **M — memory:** index size per trace, and a 4,000-call session.
- **E — eviction loss:** item-3 suite and policy family, five budgets, three filler arms (F1 benign, F2 adversarial,
  F3 identifier flood + F2).
- **Statistics:**
  - ≥ 10 launches per configuration;
  - cluster bootstrap 95% intervals (VM → launch → sample);
  - Wilson intervals for rates.

The **primary dataset is CI** (owner decision 2): GitHub-hosted `ubuntu-latest`, Node 22.23.3. It ran on
3 VMs, which drew different CPUs: AMD EPYC 7763 on VMs 1 and 3, Intel Xeon Platinum 8573C on VM 2. The eviction shards also drew an EPYC 9V74.
The CI VM is shared, not quiet. The laptop (i5-8250U, Windows 11, on AC, Balanced plan) ran only the
reduced set (owner decision 4).

## Before this run: the decision-event growth (fixed in #17)

While building M2, I found a problem: every decision event carried, and the store redacted, the session's full
lists of untrusted and secret outputs. The owner chose to fix it first, in its own PR (option B).

"Before" numbers, from an in-process probe on the laptop, 8 KiB outputs:

| untrusted outputs in the session | decision event before | decision JSON before | after (#17) |
|---|---|---|---|
| 100 | 10.5 ms | 13,617 chars | 1.8 ms, 732 chars |
| 500 | 47.7 ms | 67,617 chars | 2.7 ms, 732 chars |
| 1,000 | 94.9 ms | 135,119 chars | 1.1 ms, 734 chars |
| 2,000 | 190 ms | 272,127 chars | 1.1 ms, 742 chars |
| 4,000 | 175 ms | 546,127 chars | 0.8 ms, 742 chars |

As pre-registered, M2 (4,000 calls × 10 launches × 2 budgets) would have taken about 10 hours and measured
mostly this growth. Every number in this review is on the fixed code (`main` with #17 merged into the branch).

## Results (CI unless marked)

**Round trip: gateway − direct, p50.**

| case | `payloads: redacted` | `payloads: none` |
|---|---|---|
| 1 KiB | +16.3 ms (13.8–18.5) | +5.1 ms (4.9–5.2) |
| 64 KiB | +36.9 ms (33.9–39.2) | +28.8 ms (26.8–29.5) |
| 1 MiB | **+119 ms** (114–124) | +108 ms (105–111) |
| slash-heavy 128 KiB | +90 ms (84–94) | +82 ms (76–84) |
| real server, 64 KiB file | +41.6 ms (41.0–42.2) | — |

On the laptop, at 1 MiB: **+248 ms (215–279)**. Phase 1 measured about 37 ms there, before taint tracking existed.

**Where the 1 MiB cost goes** (share of the mean gateway overhead of 121 ms):

| stage | CI | laptop |
|---|---|---|
| `ingest` (indexing the 1 MiB output) | **59%** | 62% |
| `decide` | 13% | 14% |
| sends + pipes (`up.send`, `down.send`, unattributed) | ≈ 16% | — |
| SDK parse + validation (all 4 stages) | 3.8% | 3.6% |
| redaction | 4.0% | — |
| SQLite | 1.3% | — |

**The slash-heavy 128 KiB case:** `decide` 48% (argument decoding), `ingest` 38%. In process, the whole decision
takes p50 **39 ms** (37–40), p99 49 ms, with **0 / 3,000** policy-deadline denials.

**The 1 KiB case** is dominated by `audit.decision` (64%) and `decide` (27%). Cause: finding R7p-2. The echo
fixture repeats the same argument, which matches every earlier echo output still in Tier A.

**Hook overhead (CI):**

| comparison | 1 KiB | 1 MiB |
|---|---|---|
| hook on − hook off | −0.06 ms (−0.33–0.45) | +0.14 ms (−3.0–3.4) |
| bench entry − CLI | +0.01 ms | +1.9 ms (−0.8–5.0) |

**Run-to-run variance (CI):**
- The coefficient of variation of per-launch p50 is 1.7–12.9% for gateway arms, and up to 25.7% for the sub-ms
  direct 1 KiB arm.
- The VMs differ systematically. VM 2 (the Xeon) is about 4–5 ms faster than VMs 1 and 3 at 1 KiB redacted
  (14.0 vs 18.7 and 18.4 ms p50), and about 5 ms faster at 64 KiB.
- The three-level bootstrap carries that difference into the intervals.

**Laptop variance:** the coefficient of variation is 16.7–27.4%, with intervals about 3× wider. The laptop is
2.1–2.5× slower than CI on the gateway arms.

**Memory (M2, CI):**

| budget | Tier A, every sample | RSS at 1,000 → 4,000 calls | RSS growth after first eviction (median / max) |
|---|---|---|---|
| 32 MiB | ≤ 32.0 MiB | 190 → 201 MiB | 5.7% / 9.0% |
| 4 MiB | ≤ 4.0 MiB | 175 → 175 MiB | 23.5% / 44.9% (see P-M2) |

Every item-3 and policy trace ends with Tier A ≤ 448 bytes and ≤ 10 Tier B entries.

**Eviction (deterministic).**

| arm | budgets | what changes |
|---|---|---|
| F1 | 32, 4 MiB | nothing is evicted; nothing changes |
| F1 | ≤ 1 MiB | **partial leaks 2 → 0**: the split-secret fragments are denied fail-closed. Suite false blocks 4 → 6 / 15 (both benign sink-server traces, fail-closed). No attack succeeds. |
| F2 | every budget | the same, plus the P-E1 miss below (false blocks 7 / 12) |
| F3, policy family | every budget | **4 / 5 `from()` attacks succeed** (recipient exact / case / zero-width, webhook URL); `pol-declassify-benign` becomes a false block; **0 fail-closed denies** (R7p-3) |

The suite's 60 claimed attacks stay at 0 / 60 in every arm and at every budget.

## Predictions vs results

| prediction | result | cause of a miss |
|---|---|---|
| P-E1: the 60 trifecta-channel traces change no verdict | **missed on 1 trace** (`ben-egress-url-secret-no-untrusted`, F2/F3 → false block) | Harness. The trace's only untrusted tool is the egress `fetch_url`, so the pre-registered rule ("the trace's first step classified untrusted") made that egress tool the filler source. The filler then brought untrusted content into the session, and the trifecta check correctly blocked the next step. Not a design change (R7p-6). |
| P-E2: F1 at 32 / 4 MiB changes nothing | held | — |
| P-E3: partial leaks 2 → 0; both benign sink-server traces false-blocked (4 → 6 / 15); 0 / 12 sink attacks | held (F2/F3 show 7 / 12 because of P-E1, and their denominator is 12: 3 traces have no untrusted source) | — |
| P-E4: policy family under F1/F2 unchanged | held | — |
| P-E5: F3 → 4 / 5 policy attacks, declassify-benign false block, 0 fail-closed | **held exactly** | — |
| P-E6: Tier-B overflow alone marks nothing degraded | confirmed in code only | F3 also evicts Tier A, so the run cannot separate the two. |
| P-E7: evidence changes wherever Tier A was evicted | held (0 where nothing was evicted; 7–56 per cell elsewhere) | — |
| P-L1: laptop 1 MiB Δ p50 > 37 ms | held (+248 ms; CI +119) | — |
| P-L2: ingest largest at 1 MiB; SDK ≥ 25%; redaction + SQLite ≤ 15% | **partly missed:** ingest 59% ✓, redaction + SQLite 5.3% ✓, **SDK 3.8% ✗** | Phase 1's reading (overhead "dominated by the extra hop … the SDK parses and schema-validates") came from a single machine, before taint tracking. Measured stage by stage, the SDK costs about 5 ms of 121 ms at 1 MiB. |
| P-L3: `none` vs `redacted` at 1 MiB < 5 ms | **missed: 11.4 ms** | Redaction and storage of three events per call (B: 6.4 ms mean), plus the serialisation `none` skips. At 1 KiB the gap is also 11 ms, from R7p-2. |
| P-L4: hook on − off < 0.1 ms at 1 KiB and < 1% at 1 MiB; bench entry ≈ CLI | held on point estimates and overlapping intervals | The intervals (±0.4 ms; ±3 ms ≈ ±2.5% at 1 MiB) cannot resolve differences that small. At the slash case the bench entry is +1.0 ms (0.13–1.97) slower than the CLI; that size was not pre-registered for this check. |
| P-L5: slash case — decide largest; in-process p50 < 50 ms; 0 deadline denials | held (48%; 39 ms; 0 / 3,000) | — |
| P-L6: prose decision slower with a full Tier A | held: 0.41 → 11.1 ms (27×); 8 KiB argument 82 ms (amendment 2) | — |
| P-M1: Tier A < 64 KiB, Tier B < 1,000 per trace | held (448 bytes, 10 entries) | — |
| P-M2: Tier A ≤ budget; RSS growth after first eviction < 10% | **Tier A held; RSS held at 32 MiB (5.7% / 9.0%), missed at 4 MiB (23.5% / 44.9%)** | At 4 MiB the first eviction comes after about 116 calls, inside start-up warm-up (heap, JIT, SQLite cache). From 1,000 to 4,000 calls RSS is flat (174.6 → 175.1 MiB). The pre-registered reference point was a poor one; the result is reported as missed. |

## Findings

| id | severity | finding | resolution |
|---|---|---|---|
| R7p-1 | Medium (fixed in #17) | Decision events carried and redacted the session's full source lists: about 0.1 ms per untrusted output on every call, and unbounded in memory. | Fixed before the run (owner option B, with the owner's constraints). `test/decision-growth.test.ts` guards it. |
| R7p-2 | **Medium (open)** | **Evidence is uncapped per decision.** An argument that matches many outputs still in Tier A gets one evidence entry per output, and each is redacted into the decision event. Measured: 10 / 100 / 1,000 matching outputs give 10 / 100 / 1,000 entries and a 2.6 / 20 / 197 KB decision. The size is limited only by the index budget (a 32 MiB index holds roughly 10,000 1 KiB outputs). In L it is about 10 ms of redaction per call at 1 KiB, because the echo bench repeats its argument. A real session repeats content less, but boilerplate repeats. | Not fixed here (measure only). Proposal: cap evidence per argument path (keep the strongest few, plus a count), and charge evidence to the same bound as `sources`. Owner decision. |
| R7p-3 | **Medium (open; pre-registered P-E5)** | **Tier B overflow is silent, and `from()` deny rules do not fail closed.** An untrusted source that first floods Tier B with about 111k distinct tokens, then evicts Tier A, removes all evidence of the recipient or URL. Then 4 of 5 `from(…, "untrusted")` attacks on internal data succeed at every budget, with no degraded flag and no fail-closed deny. `may_receive` and the trifecta check are unaffected: 0 / 60 suite attacks succeed in every arm. | Not fixed here. Options: Tier-B overflow marks the session degraded; deny-side `from()` treats a degraded session as matching (fail closed, at a false-block cost); or Tier B evicts FIFO under a byte budget with the same flag. Owner decision; README known limitation added. |
| R7p-4 | Low (documented) | **The 1 MiB cost is 119 ms on CI (248 ms on the laptop), not Phase 1's 37 ms.** 59–62% of it is indexing the 1 MiB output (normalisation, fingerprints, decoding the first 128 KiB). The SDK's share is about 4%. | Recorded. DESIGN's tracked regression now has its breakdown; any optimisation goes in its own PR, measured against these numbers. |
| R7p-5 | Low (documented) | **Decisions get slower as Tier A fills**: copy and fuzzy matching scan all of it. A 64-character body goes 0.41 → 11.1 ms on a full 32 MiB index; an 8 KiB body takes 82 ms. Not deadline-denied (the deadline covers policy evaluation only), but it is latency. | Recorded. An index structure for copy matching is a possible later optimisation. |
| R7p-6 | Low (harness) | P-E1 miss: the filler-source rule can pick an egress tool. | Reported as observed; the arms are not re-run. A later eviction run should take the source from untrusted *reads* only. |
| R7p-7 | Info (fixed) | **Flaky e2e test** "approve pins definitions…" took 32.9 s against the 30 s limit under the full suite in the pre-push check (seen on #14 and again on this PR's first push); alone it takes 15 s: three CLI launches from the TypeScript sources. | Its own 180 s timeout (owner decision 5). Every pre-push check since has passed. The test still depends on an earlier test's config file (order dependence); not changed. |
| R7p-8 | Info (fixed before reading results) | Report bug: `report.mts` counted the 8 eviction-shard files as CI VMs with no latency data, so the first rendering's CI intervals were wrong (lower bound above the point estimate). | Fixed: each part uses only the files that ran it. The raw data was unaffected. |

## Not measured / code paths not exercised

- **HTTP upstreams:** only stdio was timed.
- **Resources and prompts:** only `tools/call` was broken down.
- **The global (cross-session) budget:** only per-session budgets were measured.
- **Tier B under a realistic mix:** F3 is a worst case. No measurement of how many identifiers real outputs carry.
- **RSS per trace:** M1 reports index bytes only; RSS was measured only in the long session.
- **The laptop:** only the reduced set, by owner decision. No laptop memory or eviction runs.
- **Hook overhead below ~0.5 ms:** not resolvable with these launch counts.
- **"With/without semantic layer"** (DESIGN §6): no semantic layer exists; Layer 2's cost is the `decide` stage.

## Owner review

*Drafted by Claude Code from the owner's messages in the session (2026-10-17); edited by the owner (Amineddine Znin) before merge.*

- **Verdict:** Approved as a measurement PR. It measures and changes nothing in the product except the
  test-pinned timing hook. The growth bug found while building it was fixed first in #17, as I chose. The
  pre-registration held, and every miss is reported with its cause.
- **Changed or overrode:**
  - Made GitHub-hosted `ubuntu-latest` the primary dataset, with run-to-run variance reported honestly, and saw
    `perf.yml` before its first run (decision 2). Added it to `main` alone, in #16, so it could be dispatched
    (option a).
  - Added the adversarial-filler arm: the untrusted source itself forces eviction right before the attack step,
    with attack success, partial leaks, false blocks and fail-closed denies per budget (decision 3).
  - Limited the laptop to a reduced set (1 MiB and the slash-heavy 128 KiB, ≥ 10 launches), because the machine
    has run out of memory before (decision 4).
  - Required the flaky e2e test to be fixed in this PR and logged here (decision 5).
  - Required timing through an internal, test-pinned hook with its overhead measured (decision 1).
  - For the decision-event growth, chose to fix it first in a separate PR (option B), under four constraints:
    each event still names the sources that drove it; the full list is stored once and referenced; in-memory
    lists are bounded and counted against the index budget; the probe becomes a CI test. The "before" numbers
    are in this review.
- **Accepted as known risks:**
  - The CI dataset comes from shared VMs with different CPUs; the VM-to-VM spread is in the intervals and the
    variance tables, not removed.
  - The laptop numbers cover only the reduced set.
  - Eviction ran once, in 8 shards, rather than on every replicate, since it is deterministic (amendment 3).
  - P-M2 is missed at 4 MiB because of a poorly chosen reference point; RSS is flat after warm-up.
  - R7p-2 (uncapped evidence) and R7p-3 (silent Tier-B overflow lets `from()` deny rules be evaded) are open,
    and their fixes are decided separately from this PR. R7p-3 is in the README's known limitations. Neither
    affects the trifecta invariant or `may_receive`: 0 / 60 suite attacks succeed in every arm.

---

## Addendum — the R7p-3 fix (and R7p-2), 2026-10-18

Branch `7/r7p3-tierb`. Owner decisions: 2026-10-17 and 2026-10-18 in [`docs/decisions.md`](../decisions.md).
Pre-registration [`bench/perf/PREREGISTRATION-r7p3.md`](../../bench/perf/PREREGISTRATION-r7p3.md), committed and
pushed (`5224d09`) before the rerun; two amendments, both after the CI run: CI also ran the policy family, and two
report-only changes. Results: [`bench/results/eviction-r7p3.md`](../../bench/results/eviction-r7p3.md) (before → after
against [`eviction.md`](../../bench/results/eviction.md), which is unchanged); raw data in `bench/results/perf-r7p3/`.

### What changed

- **Tier B shares the byte budget** (`src/taint/provenance.ts`).
  - Each entry is charged 288 B and each further output on an entry 40 B: the heap cost measured on Node 22
    (≈ 280 B / ≈ 34 B), rounded up.
  - Over the budget, Tier A evicts oldest first. Only once Tier A is empty does Tier B evict its oldest entries,
    and a repeated identifier moves to the newest end.
  - The 200,000-entry cap, which held ≈ 56 MB outside the budget, is gone. Tier B evictions are reported once per
    output (`tier: 'B'`, `entries`) and logged as `eviction` events.
- **Degraded state** (`src/taint/engine.ts`). A Tier B eviction marks the session degraded, as a Tier A eviction
  does: it feeds `may_receive`'s fail-closed check (R6b-1). The engine also records the integrity level of every
  output it lost track of.
- **Deny-side `from()` fails closed** (`src/policy/functions.ts`).
  - With no match, `from(v, level)` in a deny or ask rule is an error when the session lost track of an output of
    that `level`, or when attribution could not check `v` in full (over 64 KiB). The policy engine turns the
    error into a deny whose reason names the bound and the way out.
  - An error rather than `true`, so `!from(...)` fails closed too, while `false && from(...)` stays false
    (tested).
  - Allow rules and declassify conditions are unchanged.
- **R7p-2.** `capEvidence` keeps the strongest 4 entries per argument (32 per decision), always including the one
  a `may_receive` deny cites, plus `evidenceOmitted`. `mcphantom trace` prints the count. Measured on the review's
  shape (a 1 KiB argument repeated in every output): 10 / 100 / 1,000 matching outputs give a decision of 1,552 /
  1,563 / 1,574 characters. Before: 2.6 / 20 / 197 KB.
- **Tests:** `test/tierb-budget.test.ts` (13 tests). Two existing tests had budgets of 200 bytes and of 1.5 × one
  output's Tier A size; they were resized so that only Tier A evicts, and now assert the tier.
- **Harness:** `bench:perf --sets / --out-dir`; a per-ingest index-bound check (Q-8); `report-eviction.mts`.
  `perf.yml` gained two choice inputs (`jobs`, `out_dir`) so the eviction shards can run alone.

### Rerun

- **CI:** `perf.yml` run [39088191904](https://github.com/Amineddine/mcphantom/actions/runs/39088191904) on
  `5224d09`, eviction job only, 8 shards, both sets (amendment 1). It took about 10 minutes, against about 3
  CPU-hours for item 5's eviction run. Observed, not measured further. The likely cause is that Tier B no longer
  grows to 200k entries under F3.
- **Laptop:** the policy family, as registered. Its 128 rows are **identical** to CI's policy rows, trace by
  trace, including the index-bound field.

### Predictions vs results

| prediction | result |
|---|---|
| Q-1 policy family 0 / 5 in every cell; under F3 denied on evidence; `pol-declassify-attack` stopped by its rule | **held** — F3 4 / 5 → 0 / 5 at every budget; no claimed attack has a fail-closed deny |
| Q-2 partial leaks 0 / 5 | held |
| Q-3 false blocks 2 / 2 in F1 ≤ 1 MiB, F2 and F3 at every budget; F0 and F1 at 32 / 4 MiB 0 / 2 | **held exactly** (both benign traces denied fail-closed by the deny rule) |
| Q-4 3 fail-closed traces per Q-3 cell, 0 elsewhere | held |
| Q-5 `out-pol-recipient-spelled-out` 1 / 1 → 0 / 1 in the Q-3 cells | held (a side effect of failing closed, not a new claim) |
| Q-6 suite unchanged; F3 fail-closed may fall | held — 0 / 60, partial leaks and false blocks identical in every cell; F3 fail-closed traces 9 → 4 (evidence is found first) |
| Q-7 Tier B evictions only in F3, every trace | held (80 / 80 suite, 8 / 8 policy; 0 elsewhere) |
| Q-8 index ≤ budget after every ingest | **missed** — 418 of 1,335 traces, all F3, over by at most 270 bytes (R7p-9) |
| Q-9 M1 entry counts unchanged; Tier B bytes reported | counts held; the bytes table was missing and was added to the report after the run (amendment 2): suite 576 B, policy 1,728 / 2,880 B (median / max) |

### Findings

| id | severity | finding | resolution |
|---|---|---|---|
| R7p-3 | Medium | (see above) | **Fixed** in this PR; 0 / 5 under the flood at a cost of 2 / 2 benign policy traces under eviction. README limitation rewritten. |
| R7p-2 | Medium | (see above) | **Fixed** in this PR; decision size constant (≈ 1.5 KB at 1,000 matches). |
| R7p-9 | Low (open) | **The index can exceed its budget right after an ingest, by one output's source-summary growth.** `TaintEngine.ingest` grows the source summary and calls `chargeExternal` after `index.add()` has already trimmed. The new charge is applied at the next ingest. Seen only under F3, where Tier B alone fills the budget: at most 270 bytes over. It predates this PR (#17). | Not fixed here: this PR's code stays what was measured (owner decision). Its own PR follows: trim again after the summary is charged, a test, and a Q-8 recheck on F3. |
| R7p-10 | Info | The full-suite `npm run check` once timed out the CLI e2e test "runs as a stdio gateway for a real MCP client…" at 30 s under load. Alone it passes (5 / 5, 52 s), and the pre-push run passed 531 / 531. It is the same load pattern as R7p-7, in a different test. | Fixed in this PR (owner decision): the whole file gets a 180 s timeout; each launch keeps its 60 s cap. |

### Not tested / not measured

- **A Tier B flood sent after the recipient, then an attack.** Covered at the decision level only
  (`test/tierb-budget.test.ts`); the harness has no such arm.
- **Losing track through partial decoding** (an untrusted output over 128 KiB) driving the `from()` fail-closed
  path. The code shares the eviction path, but no test exercises it.
- **Latency of the fix.** L, B, D and M2 were not rerun; item 5's numbers stand. The fix adds a map delete + set per
  repeated identifier on ingest, and work at decision time only for a `from()` with no match.
- **The global (cross-session) budget, HTTP upstreams:** as in item 5.
- **The allow-side hole** (`!from()` in an allow rule or declassify condition in a degraded session): the next PR,
  by owner decision.

### Owner review — Amineddine Znin

- **Verdict:** Approved to merge once CI is green. I approved the plan as written before any code, and the rerun
  as the policy family on the laptop and the full suite on CI.
- **What I decided:**
  - R7p-3 combines all three fixes: a Tier B byte budget with oldest-first eviction; overflow marks the session
    degraded; deny-side `from()` fails closed in a degraded session.
  - R7p-2 goes in this PR.
  - R7p-9 is not fixed here: this PR's code stays exactly what was measured. It gets its own small PR right
    after, with a test and a Q-8 recheck on the F3 arm.
  - R7p-10: the whole `test/cli.e2e.test.ts` file gets a 180 s timeout, in this PR.
  - The allow-side `!from()` hole is the next PR after that, with its own lint rule, tests and a policy-family
    measurement.
- **Known and left open:** R7p-9 until its PR; the allow-side hole until its PR.

---

## Addendum — the R7p-9 fix, 2026-10-18

Branch `7/r7p9-index-bound`. Owner decision: 2026-10-18 in [`docs/decisions.md`](../decisions.md) (R7p-9 in its
own PR, after #18).

- **Cause.** `TaintEngine.ingest` grew the source summary and called `chargeExternal` after `index.add()` had
  already trimmed. The new charge applied only at the next ingest, so the index could sit over its budget by one
  output's summary growth. Q-8 of the R7p-3 rerun found it: 418 / 1,335 traces, all F3, at most 270 bytes over.
- **Fix** (`src/taint/provenance.ts`, `src/taint/engine.ts`). The eviction loop is now `ProvenanceIndex.trim()`.
  `chargeExternal()` calls it at once, and the engine treats those evictions like any other: logged, and the
  session is marked degraded.
- **Test.** `test/tierb-budget.test.ts` floods Tier B, then ingests 20 outputs from new sources. The index must
  fit its budget after every ingest. It passes on the fix, and fails on the old code at 65,710 bytes against a
  65,536-byte budget.
- **Q-8 recheck.**
  - Run: `perf.yml` [39092881360](https://github.com/Amineddine/mcphantom/actions/runs/39092881360) on `32bb1a2`,
    eviction job only, all arms, into `bench/results/perf-r7p9/`. `perf.yml` gained that one `out_dir` choice.
  - Result: **0 / 1,335 traces over the budget after any ingest** (was 418).
  - Every one of the 1,426 rows has the same outcome, decisions and evidence as the R7p-3 run; only the index byte
    counters differ.
  - Report: [`bench/results/eviction-r7p9.md`](../../bench/results/eviction-r7p9.md).
- **Not tested.** The global (cross-session) budget, as before.

### Owner review — Amineddine Znin

- **Verdict:** R7p-9 fixed in its own small PR right after #18, as I decided, with a test and Q-8 rechecked on
  the F3 arm.
- **What I decided:** #18's code stays exactly what was measured; this fix goes in its own PR. Trim again after
  the source-summary charge, add a test, recheck Q-8 on F3.
