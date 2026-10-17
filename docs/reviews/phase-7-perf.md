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
