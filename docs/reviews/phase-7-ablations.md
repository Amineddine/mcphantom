# Phase 7 item 4 — baselines and ablations: review

Branch `7/pr4-ablations`. Pre-registration `bench/attack/PREREGISTRATION-ablations.md`, committed and pushed
(`9659015`) before the first run; run once. Results: [`bench/results/ablations.md`](../../bench/results/ablations.md)
(`npm run bench:ablations`), pinned in `test/attack-bench.test.ts`. Owner decisions for this item: 2026-10-16 in
[`docs/decisions.md`](../decisions.md).

## What was measured

Decision-level replay (as in item 3) of three trace sets, never pooled, through 3 baselines and 14 MCPhantom
configurations:

- **Item-3 suite** (83 traces, unchanged);
- **Policy family** (8 traces, owner addition): an author-written `deny: from(arg.to | arg.url, "untrusted")` on two
  egress tools and a `declassify` for directory recipients;
- **Unclassified-source family** (9 traces): secrets read from a tool with no confidentiality set.

The configurations:

- Layer 1 only, with and without the argument credential check;
- each Layer-2 matcher off in turn;
- scanner off;
- entropy `on_hit` `internal` / `secret`;
- `may_receive_mode: context`, also combined with Layer 1 only;
- trifecta in audit mode.

Every table reports attack success, partial leaks, false blocks and utility under attack, with Wilson 95%
intervals, and lists every trace whose outcome differs from defaults.

The matchers are switched off through an internal hook: `ProvenanceIndex` takes a matcher set, and `TaintEngine`
takes a third constructor argument. No configuration can reach the hook, and the gateway and the CLI never pass it
(`test/ablation-hook.test.ts`). With every matcher on, the code path is unchanged.

## Results

- **Under the default configuration Layer 2 does not change any trifecta decision.** The invariant reads the
  Layer-1 context label only. With all five matchers off, or any one of them off, the 48 egress-url / egress-body /
  exec / write-outside traces score exactly as at defaults (pinned).
- **Where Layer 2 does decide** (`may_receive` and `from()` rules), turning it off changes the outcome:
  - Item-3 suite: 0 → 7/60 claimed attacks succeed, all on the bounded sink server: the random token under every
    encoding, plus the split AWS key. Turning the argument credential search off as well gives 12/60.
  - Policy family: 0 → 4/5 internal-data attacks succeed (the trifecta check does not guard `internal` data), and
    the declassified benign trace becomes a false block (0 → 1/2).
- **The trifecta check carries the rest.** In audit mode 48/60 attacks succeed (every trifecta-channel trace) and
  the 4 over-tainting false blocks disappear.
- **The partial-leak case (owner rule i).** `may_receive_mode: context` closes it: 0 fragments delivered on both
  split3 sink-server traces, with no Layer 2 needed (Layer 1 only + context gives the same). The cost is 2 extra
  false blocks (4 → 6 of 15). One of them was not predicted (R7a-1). Added to the README known limitations.
- **Matchers one at a time:**
  - `decoded` off: 4 random-token sink traces get through (base64, hex, url, reverse).
  - `cumulative` off: both split3 partial leaks become full successes.
  - `exact`, `normalized`, `fuzzy` off: no change on any set. `exact` is backed up by `normalized`; for
    `normalized`, see R7a-2.
- **Entropy (unclassified source).** At defaults and with `on_hit: internal`, the 3 random-token attacks get
  through; the 3 AWS-key controls are blocked through pattern detection. `on_hit: secret` stops all 6, at 1/3
  false blocks (the random-shaped reference); the UUID and hex-digest controls stay delivered.
- **Scanner off:** no change anywhere. The definitions are inert, so the scanner hides nothing by construction (as
  item 3 documented).

## Predictions vs results

| prediction (pre-registered) | result | cause of a miss |
|---|---|---|
| Layer 2 changes no trifecta decision | **held** | — |
| C1 Layer 1 only: ~11/12 sink-server attacks succeed | **missed: 7/12** | The argument credential search (`secretRuleIn`) also searches **decoded** forms (first 32 KiB), not clear text only, so the AWS key stays blocked under base64/hex/url/reverse. A comment in `engine.ts` said "in clear text"; corrected (R7a-3). |
| C1x: 12/12 | held | — |
| C3 `decoded` off: 8 sink-server traces get through | **missed: 4** (random token only) | Same cause: the credential search decodes the AWS key itself. |
| C6 `cumulative` off: split3 partial leaks become full successes | held | — |
| C2, C4, C5 (`exact`, `normalized`, `fuzzy` off): no change on the suite | held | — |
| C7 scanner off, C8, C9: no change on the suite | held | — |
| C10/C11 context mode: 0 partial leaks, **+1** false block | **partly missed: +2** | `ben-sink-server-untrusted-no-secret` is blocked too: the web page tool has no confidentiality set, defaults to `internal`, and `internal` is above `public` (R7a-1). |
| C12 audit mode: 48 trifecta-channel attacks succeed, over-tainting false blocks disappear | held | — |
| Policy C0, C1/C1x/C11, C2 | held | — |
| Policy C3 `normalized` off: case-changed and zero-width recipients get through | **missed: no change** | The `decoded` matcher compares normalized hashes. A rot13 variant indexed on the output side and the argument's rot13 variant meet case-insensitively, so normalization still happens inside `decoded` (R7a-2). |
| Policy C4–C6: no change | held | — |
| Policy, every other configuration: no change | **missed for C9** | The policy family's internal canary is a random token, so `on_hit: secret` raises it to `secret` and the trifecta check fires: `pol-recipient-trusted` becomes a false block, and the outside-claims trace is stopped (R7a-4). |
| Unclassified C0/C8, C9, C12 | held | — |

## Findings

| id | severity | finding | resolution |
|---|---|---|---|
| R7a-1 | Medium (documented) | **`may_receive_mode: context` blocks more than the docs implied.** Any output of a tool with no confidentiality set is `internal` (the secure default), so on a `may_receive: public` server one unclassified read is enough to block every later call; reading a secret is not needed. | README limitation states it, with the measured cost. Whether `suggest` or `init` should warn when `context` is combined with `public` is left to the owner. |
| R7a-2 | Low (documented) | **The matchers are not independent.** `decoded` looks identifiers up by normalized hash, so "normalized off" removes only the direct normalized path. The measured contribution of `normalized` alone is therefore a lower bound. | Stated in the results and here. A cleaner cut would need a second hash scheme; not worth it for an ablation. |
| R7a-3 | Low (fixed) | `engine.ts` described the `may_receive` credential search as clear text only; it also decodes the first 32 KiB of each field. | Comment corrected; no behaviour change. |
| R7a-4 | Low (accepted) | **Trace-design interaction in the policy family.** The internal canary is random-shaped, so C9 measures entropy, not policy, on that family. | Reported as observed. The traces are not edited after the run (pre-registration rule). A later family should use a low-entropy canary for internal data. |
| R7a-5 | Low (accepted) | The unclassified-source attacks carry the schema default `claimed: true` in their JSON, although the design does not claim them at defaults. | The runner and the report treat the family on its own and never pool it. Fix it in the scenario file at the next trace change, as an amendment. |
| R7a-6 | Info | `from(…, "untrusted")` is precision-mode: a recipient the page spells out in words and the model reassembles gets through at defaults (outside the claims, 1/1). | As designed; README already lists model-constructed URLs and addresses. |

## Not measured / code paths not exercised

- **No live models.** These are author-written traces, so they measure which part of the design stops what, not
  attack rates (Phase 9).
- **Benign sets are tiny:** 15 + 2 + 3 traces. The false-block numbers describe these mixes, not a workload
  (PostHog in item 7).
- **`from()` paths not covered:** `from()` on the deny side with fuzzy or cumulative evidence (no policy trace edits
  prose); `ask` rules; `declassify` grounded through `normalized` or `decoded` evidence.
- **Fail-closed paths not covered:** the `may_receive` paths for attribution bounds and eviction; no trace reaches a
  bound.
- **Bounds not tried:** `may_receive: internal`, and context mode on it.
- **The hook under eviction:** matcher switches combined with Tier-A eviction or Tier-B overflow are untested.
- **Other channels:** the black-box tier was not rerun for ablations (decision level only, as in item 3).

## Owner review

*Draft from the owner's messages in this session; the owner edits this section before merge.*

- **Verdict:** Approved. The ablations answer the question I asked: what each layer actually contributes. Under the default config, Layer 2 does not change any trifecta decision. Its value is where it decides on its own: may_receive-bounded servers (0 → 7/60 attacks succeed without it) and from() policies (0 → 4/5). Trifecta in audit mode lets 48/60 through, which confirms Layer 1 is the core protection.
- **Changed or overrode:**
  - Added the `from()` policy family, so Layer 2 is measured where it is designed to work. Without it the ablation
    would understate Layer 2.
  - Required the report to say plainly that under the default config Layer 2 does not change trifecta decisions.
  - Approved the unclassified-source traces for entropy `on_hit` (decision 1).
  - Kept the argument credential check in "Layer 1 only", with an extra row without it (decision 2).
  - Added trifecta audit mode (decision 3).
  - Approved the internal matcher hook, on condition of a test proving the configuration cannot reach it
    (decision 4).
  - Earlier rules applied: ablate the partial-leak case and report it either way in the README; partial leaks
    are their own metric in every table.
- **Accepted as known risks:** * Accepted as known risks:
  - R7a-1: context mode costs false blocks (4 → 6 of 15) because tools with no confidentiality set count as internal. Accepted because it's opt-in and documented. Follow-up: init prompts users to classify tools and warns about context mode's false-block cost.
  - Evidence mode can leak the first fragments of a split secret to a bounded server before blocking. Context mode closes it; documented in the known limitations.
  - R7a-2 (matchers share normalized hashes, so "normalized off" is a partial cut), R7a-4 (the policy family's random-shaped canary made one row measure entropy; the next family uses a low-entropy canary) and R7a-5 (policy traces mislabelled claimed: true; reported separately, fixed at the next trace change): low severity, accepted. None affects protection.
