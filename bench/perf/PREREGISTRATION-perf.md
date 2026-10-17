# Pre-registration — Phase 7 item 5: latency, memory, eviction loss

Committed and pushed **before** any harness in `bench/perf/` runs for the first time. Owner decisions:
2026-10-17 in [`docs/decisions.md`](../../docs/decisions.md). The predictions below are locked by this commit.
Anything changed after it is an amendment, dated and listed at the end, never a silent edit.

## Rules

1. **This PR measures; it optimises nothing.** No detector, matcher, decoder, policy, label or eviction
   change. The only `src` change is an internal **timing hook**: an optional `timings` sink on `Gateway` and
   `SqliteStore`. No configuration can reach it, and the CLI never passes it (test-pinned, like the item-4
   ablation hook). With no sink, the code path takes no extra `performance.now()` calls.
2. **Launches.** Every latency, breakdown, decision-level and long-session configuration runs as **≥ 10
   independent process launches**. A launch is a fresh `node` process, started sequentially by the launcher.
   Within a launch the arms are interleaved in blocks, and the arm that goes first alternates with the launch
   number.
3. **Statistics.**
   - Percentiles use the nearest rank on the pooled samples (as in Phase 1).
   - 95% intervals use a cluster bootstrap with B = 2000 and a fixed seed of 20261017. The bootstrap
     resamples launches, then samples within each launch.
   - On CI the bootstrap resamples **VM → launch → sample**, because calls inside one process (and launches
     on one VM) are correlated, so pooling them would make the intervals too narrow.
   - Gateway − direct deltas are bootstrapped paired at the launch level (the same resampled launches for
     both arms).
   - Rates (attack success, partial leaks, false blocks, utility, deadline denials) carry Wilson 95%
     intervals.
4. **Run-to-run variance is reported, not averaged away.** For each configuration the report gives:
   - p50 per launch (min / median / max) and the coefficient of variation of the launch p50s;
   - on CI, p50 per VM and the spread between VMs.
5. **Run once.** The CI dataset is one `workflow_dispatch` run of `.github/workflows/perf.yml`: three
   replicate jobs, each on its own fresh GitHub-hosted `ubuntu-latest` VM, after the owner has seen the
   workflow file. The laptop dataset is one run of the reduced set.
   - A job that fails for an infrastructure reason may be re-run once; that is recorded as an amendment.
   - Smoke runs used to debug the harness after this commit pass `--smoke`; they are never reported.
6. **Every miss against a prediction is reported**, with its cause where one is found, and is not fixed in
   this PR.

## Environments

| id | where | what runs |
|---|---|---|
| CI (primary dataset, owner decision 2) | GitHub-hosted `ubuntu-latest`, Node 22, 3 replicate VMs in one dispatch | everything below |
| Laptop (owner decision 4) | the owner's i5-8250U, Windows 11, plugged in, nothing else running | the reduced set R only |

The CI runner is a **shared VM, not a quiet machine**. The report says so and shows the VM-to-VM spread.
Each results file records the CPU model, core count, memory, OS, Node version and git commit, plus the
laptop's power state.

## L — round-trip latency (`bench:perf -- latency`)

`tools/call` round trips, direct to the echo fixture (`test/fixtures/servers/everything.ts`) vs through the
built CLI (`dist/cli/main.js run`). Calls are sequential, with no pipelining. The fixture echoes its argument,
so the output is the same size as the input. The fixture's tool keeps the global default classification
(`egress`, `untrusted`, `internal`): every call is decided, attributed and ingested, as an unclassified tool
would be.

| size | argument | warmup / measured calls per launch |
|---|---|---|
| 1 KiB | `x` × 1,024 | 20 / 200 |
| 64 KiB | `x` × 65,536 | 20 / 100 |
| 1 MiB | `x` × 1,048,576 | 5 / 20 |
| 128 KiB slash-heavy (R6b-10) | `aBcdefghijklmnoP/` × 7,710 (131,070 characters, within the 128 KiB argument decode budget) | 5 / 40 |

- **Logging:** each size runs with `logging.payloads: redacted` (default, `max_payload_bytes` 65,536) and
  with `payloads: none`.
- **Real server (CI only):** `@modelcontextprotocol/server-filesystem` `read_text_file` on a 64 KiB file,
  direct vs gateway, default logging, 20 / 100 calls.
- At 1 MiB the 32 MiB provenance index fills after about 15 calls, so later calls also evict and log an
  eviction event. That is what an unclassified 1 MiB tool costs; the report states it.

## B — cost breakdown (`bench:perf -- breakdown`)

The same calls through `bench/perf/timed-gateway.mts`, a bench-only entry that builds the gateway from
`dist/` exactly as `mcphantom run` does, plus the timing sink. Sizes: 1 KiB, 1 MiB, slash-heavy 128 KiB;
default logging. Stages of one `tools/call`, timestamped inside the gateway process:

| stage | what it covers |
|---|---|
| `down.parse` | downstream request: JSON parse + JSON-RPC schema check (SDK `ReadBuffer`) |
| `down.validate` | SDK dispatch and `CallToolRequestSchema` validation, up to the handler |
| `resolve` | route lookup |
| `decide` | Layer-2 attribution + policy + invariant |
| `audit.decision` | decision event: redaction + SQLite write |
| `sent` | cumulative-matcher record |
| `up.send` | serialise + write to the upstream pipe |
| `up.wait` | upstream pipe + fixture, up to the response's arrival |
| `up.parse` | upstream response: JSON parse + JSON-RPC schema check |
| `up.validate` | SDK result validation, up to `callTool` resolving |
| `ingest` | secret detection + indexing of the output |
| `audit.ingest` | taint/eviction events: redaction + SQLite |
| `audit.request` | request event (arguments + result): redaction + SQLite |
| `down.send` | serialise + write of the response to the client |

- In `SqliteStore`, redaction and the SQLite insert are timed separately, so every `audit.*` stage also
  splits into `redact` and `store.write`.
- **Gateway overhead** = client round trip − `up.wait`. The part of the round trip no stage covers is
  reported as **unattributed** (pipe transfer to and from the client, event-loop scheduling).
- **Hook overhead:** at 1 KiB and 1 MiB, three interleaved arms per launch: the CLI; the bench entry with
  the hook off; the bench entry with the hook on.
- `down.parse`, `down.send`, `up.send` and `up.parse` are measured by wrapping SDK prototypes **inside the
  bench entry only**. They are never wrapped in the product.

## D — decision level, in process (`bench:perf -- decision`)

The `bench:policy` configuration (a tool with `containsSecret`, `glob`, `from`, `ask` and `within` rules).
Each launch is a fresh process.

| case | calls per launch |
|---|---|
| small arguments | 2,000 |
| 128 KB body (`a ` × 65,536) | 100 |
| 128 KB slash-heavy body (R6b-10) | 100 |
| 1 MiB body (policy size check: fast deny) | 50 |
| 64-character prose body, empty index | 500 |
| 64-character prose body, Tier A filled to its 32 MiB budget with 8 KiB prose outputs | 200 |

- Whole-decision p50 / p95 / p99 with CIs.
- Calls denied by the 50 ms policy deadline (k / n, Wilson), i.e. how often the deadline fails closed.

## M — memory (`bench:perf -- memory`)

- **M1, per trace (deterministic):** each item-3 and policy-family trace replayed at defaults in process.
  Tier A bytes and outputs, Tier B entries and sink characters at the end of the trace, reported as a
  distribution (median, max) and per category.
- **M2, long session (10 launches per budget):** 4,000 sequential calls through the bench entry (a real
  gateway process), each echoing 8 KiB of identifier-free prose, at `max_index_mb` 32 and 4. Every 100 calls
  the gateway reports its RSS, `heapUsed`, Tier A bytes and Tier B entries.

## E — eviction loss (`bench:perf -- eviction`, deterministic, in process)

**Sets:** the item-3 suite (83 traces, unchanged) and the policy family (8 traces, unchanged). They are
reported in separate tables. Outside-the-claims traces go in their own table.

**Budgets:** `taint.max_index_mb` = 32, 4, 1, 0.25, 0.0625 MiB.

**Insertion point:** immediately before the first attack step (attack traces), or before the last step
(benign traces).

| arm | what is inserted |
|---|---|
| F0 | nothing — the reference, run at defaults |
| F1 benign filler (owner decision 3) | 128 outputs × 8 KiB of identifier-free prose from `docs/read_doc` (read, trusted, public), at the insertion point |
| F2 adversarial filler (owner decision 3) | the trace's own untrusted source tool (its first step classified untrusted) called N = ⌈1.1 × budget / 64 KiB⌉ times at the insertion point; each call returns 64 KiB of identifier-free prose (≥ 128 KiB of Tier A each, so everything indexed earlier is evicted) |
| F3 identifier flood + F2 (added by Claude Code, flagged for the owner) | before the trace's first step, the same untrusted source returns 56 outputs of 64 KiB, each made of distinct random 32-character tokens (≈ 111k tokens, against Tier B's 200,000-entry cap at 2 entries per token); then F2 |

**Why F3 is included.** Tier B never evicts: once full, it silently drops new identifiers. An attacker who
floods Tier B before the sensitive reads, then evicts Tier A, removes both kinds of evidence. F2 alone leaves
Tier B intact.

**Rules:**
- Filler tokens and prose are generated at run time from a fixed seed; no filler content is committed.
- A trace with no untrusted source has no F2/F3 row (reported as n/a).
- Filler steps are excluded from every oracle. Utility and false blocks count the trace's own steps only.

**Metrics per (set, arm, budget):**
- attack success, partial leaks, false blocks, utility under attack (Wilson);
- **fail-closed denies** — decisions on the trace's own steps denied with a `fail-closed` reason;
- **verdict changes** and **evidence changes** vs F0. Evidence is keyed by argument path, the trace step the
  output came from, kind and matcher.
- Tier A evictions, Tier B entries, and whether Tier B reached its cap.
- Every trace whose outcome differs from F0 is listed.

## Predictions

**Eviction (E).**

| id | prediction |
|---|---|
| P-E1 | The 60 trifecta-channel traces (egress-url, egress-body, exec, write-outside; 48 attacks + 12 benign) change no verdict in any arm at any budget: Layer-1 labels are a running join and are never evicted. |
| P-E2 | F1 at 32 and 4 MiB evicts nothing; every outcome equals F0. |
| P-E3 | F1 at 1, 0.25 and 0.0625 MiB, and F2 and F3 at every budget, on the suite: sink-server attacks 0 / 12 succeed. **Partial leaks drop from 2 to 0**: the first fragment is denied fail-closed, because the secret's output was evicted. Both benign sink-server traces become false blocks (fail-closed; the evicted page counts as `internal`), so suite false blocks go 4 → 6 / 15. |
| P-E4 | Policy family under F1 and F2, every budget: no verdict change. The recipient address and webhook URL survive Tier-A eviction in Tier B. |
| P-E5 | **Policy family under F3, every budget: the four internal-data attacks succeed (0 → 4 / 5).** These are recipient exact / case / zero-width and webhook URL: `from(…, "untrusted")` is precision-mode and finds no evidence, and no `may_receive` bound fails closed. `pol-declassify-attack` stays stopped (trifecta). `pol-declassify-benign` becomes a false block (0 → 1 / 2), because the declassify can no longer ground its trusted recipient. `pol-recipient-trusted` stays delivered. No fail-closed deny fires in the policy family. |
| P-E6 | Under F3, the Tier-B overflow on its own marks no decision degraded: there is no overflow signal today. |
| P-E7 | Evidence changes are nonzero wherever Tier A was evicted (copy evidence disappears). Their number is reported, not predicted. |

**Latency (L, B, D).**

| id | prediction |
|---|---|
| P-L1 | On the laptop, gateway − direct p50 at 1 MiB exceeds Phase 1's ≈ 37 ms, because ingest (indexing 1 MiB of output) did not exist in Phase 1. |
| P-L2 | At 1 MiB: `ingest` is the largest gateway stage. The SDK stages on the gateway (`down.parse` + `down.validate` + `up.parse` + `up.validate`) are ≥ 25 % of gateway overhead; `redact` + `store.write` together are ≤ 15 %. |
| P-L3 | `payloads: none` vs `redacted` changes gateway − direct p50 at 1 MiB by < 5 ms. |
| P-L4 | Hook on vs hook off: Δ p50 < 0.1 ms at 1 KiB and < 1 % at 1 MiB. Bench entry with the hook off vs the CLI: overlapping 95% intervals. |
| P-L5 | Slash-heavy 128 KiB: `decide` is the largest gateway stage (argument decoding). In-process whole-decision p50 is < 50 ms on CI, with 0 deadline denials: the deadline covers policy evaluation only. |
| P-L6 | The 64-character prose decision is slower with a full 32 MiB Tier A than with an empty index (copy and fuzzy matching scan all of Tier A). By how much is reported, not predicted. |

**Memory (M).**

| id | prediction |
|---|---|
| P-M1 | Every item-3 and policy-family trace ends with Tier A < 64 KiB and Tier B < 1,000 entries. |
| P-M2 | In the long session, Tier A bytes never exceed `max_index_mb` at any sample (a hard invariant). RSS plateaus once Tier A reaches its budget: RSS growth from that point to the end is < 10 % of the RSS at that point. |

## The reduced laptop set R (owner decision 4)

- L at 1 MiB and at the slash-heavy 128 KiB, default logging only: direct vs gateway.
- B at the same two sizes.
- ≥ 10 launches each.
- Nothing else; in particular, no M2 and no E on the laptop.

## Amendments

None yet.
