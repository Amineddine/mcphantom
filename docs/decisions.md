# Owner decisions

A dated log of the decisions I (Amineddine Znin, the owner) made on MCPhantom. Each entry gives the decision,
the options considered, my reason and the PR that carries it. Implementation detail lives in
[DESIGN.md](DESIGN.md) and the reviews in [reviews/](reviews/).

Entries up to 2026-10-16 marked *compiled from records* were backfilled once from DESIGN.md's change log and
resume point, the phase reviews and the PR history. Where those records do not say which options were
weighed or why, the entry says "not recorded" rather than reconstructing a reason. Before PR #1
(2026-10-14) work was committed directly, so those entries have no PR.

PR links: `#N` = https://github.com/Amineddine/mcphantom/pull/N.

## 2026-10-12

- **Initial plan approved, with changes.** Vertical slice by end of Phase 2; gateway only for v1 (wrap mode
  deferred); bounded provenance memory whose eviction never weakens Layer 1; storage hardening and same-user
  tampering in the threat model; Apache-2.0; benchmark named `mcp-attack-bench`. Options and reasons: not
  recorded. PR: none. *Compiled from records.*
- **Libraries: CEL via `@bufbuild/cel` over a hand-written parser; `better-sqlite3` over `node:sqlite`.**
  Options as named. Reason: not recorded (DESIGN.md §3–4 hold the design rationale). PR: none. *Compiled from
  records.*
- **No-API-credit operation.** Ollama by default, Claude Code for the demo, the Anthropic backend capped at
  USD 50 with per-batch confirmation. Reason: not recorded. PR: none. *Compiled from records.*
- **A `write` outside its declared workspace counts as `egress`** (Phase 2 finding A1: the trifecta check
  missed `write`). Options: leave `write` outside the invariant, or treat outside targets as egress. Reason:
  writes to synced or remote targets are exfiltration. PR: none. *Compiled from records.*
- **Phase 9 showcase must use real Claude Code against a real poisoned page**, with a replay fallback, and
  `npx mcphantom demo` must work from the installed package. Reason: not recorded. PR: none. *Compiled from
  records.*
- **Scanner follow-ups (Phase 3 review).** Fix B2 now: concatenate a tool's descriptions so an instruction
  split across properties is caught. Run the scanner through Layer 2's normalize/decode pipeline once that
  pipeline is reusable (closes B1/B3/B4). Reason: not recorded. PR: none. *Compiled from records.*
- **Lockfile HMAC scope stated precisely (Phase 4).** The key sits in an owner-only file, and the docs say
  what that does and does not protect rather than implying more. Reason: not to overstate a guarantee. PR:
  none. *Compiled from records.*
- **Policy engine rules (Phase 5 owner notes 1–3).** A rule naming an absent argument fails closed. CEL gets
  a cost budget (AST and argument limits, 50 ms predicate deadline). `suggest` labels annotation-derived
  classifications "server-claimed", and `--write` applies only tightening suggestions. Reason: not recorded.
  PR: none. *Compiled from records.*
- **Resource pinning before v1** (Phase 5 owner note 4). Options: before or after v1. Reason: not recorded.
  PR: none. *Compiled from records.*

## 2026-10-13

- **Roadmap update.** Semantic-embeddings layer dropped from v1; v1 dashboard = taint-trace view only; a v0.1
  public release right after 6a; new Phase 10 "v1 hardening"; docs and release renumbered to Phase 11.
  Reason: not recorded. PR: none. *Compiled from records.*
- **`from()` on the allow side counts only deterministic evidence** (exact / normalized / decoded); fuzzy and
  cumulative evidence never grounds an allow or a declassify. Reason: similarity must not be able to lift a
  block (R6a-1). PR: none. *Compiled from records.*
- **`ask` without elicitation is a deny in v0.1**; a minimal approval queue moves into the v1 trace view
  (Phase 8). Options: deny, a v0.1 queue, or a v1 queue. Reason: not recorded. PR: none. *Compiled from
  records.*
- **Release policy for v0.1.0.** Vulnerability reports through private GitHub advisories only; npm
  publication waits for v1. Reason: not recorded. PR: none. *Compiled from records.*
- **SDK progress race reported upstream as a comment on typescript-sdk #2580** before the repository went
  public; the drafts already in history stay published (R6.5-4, accepted). Options: our own issue/PR, a
  comment, or rewriting history (denied: no force pushes). PR: none. *Compiled from records.*
- **`may_receive` built in 6b, together with the "server that is itself the sink" attack server**, in two
  modes: Layer-2 evidence always on (restriction only), `context` mode opt-in per server, unset = no bound.
  Reason: not recorded. PR: #3. *Compiled from records.*
- **Entropy-only hits default to `record`** (redacted and logged, label unchanged); a PostHog `phx_` key rule
  is added. Reason: entropy cannot tell a key from a random id. PR: #2. *Compiled from records.*
- **Unlicensed third-party poisoned examples are rewritten as "derived from [source]"**, with attribution;
  copied verbatim only where the licence allows. Reason: not recorded. PR: #5. *Compiled from records.*
- **PostHog as a real-world target**, scoped as follows. A static scan of its MIT tool definitions plus a
  fixture-server scenario in 6b. All adversarial work runs on fixtures or a local server against a mock
  backend, never PostHog cloud. The crafted cloud event is dropped. Reason: the Bugcrowd brief's scope and
  fairness to PostHog. PR: #7. *Compiled from records.*

## 2026-10-14

- **Every 6b PR is squash-merged, and only after CI passes and I confirm.** Reason: not recorded. PR: #1
  onwards. *Compiled from records.*
- **A scanner miss is fixed only from a dev-split example written first**, never from the held-out item.
  Reason: keep the held-out split independent. PR: #5. *Compiled from records.*
- **Keep the one commented `.gitleaksignore` fingerprint** for the gitleaks false positive in synthetic
  corpus data. Options: keep it or rewrite history (denied). PR: #5. *Compiled from records.*
- **The pre-push hook keeps its full output in a log file.** Reason: a failing check's output was lost in
  6b. PR: #4. *Compiled from records.*
- **Do not retry server-backed exfiltration scenarios** after a safety classifier stopped them twice; cover
  the channels at the decision level instead. PR: #8. *Compiled from records.*
- **Fresh held-out poisoned set added to Phase 7**, from new third-party sources, frozen before running.
  Reason: the 6b scanner test split had been observed. PR: #11. *Compiled from records.*

## 2026-10-15

- **Phase 7 plan and order:** R6b-1 → fresh held-out set → runtime benchmark → baselines/ablations →
  latency → AgentDojo port → PostHog in CI. Thesis measurement goes to Phase 9; only its classifier is in
  Phase 7. Sessions hand off at ~75% context. Reason: not recorded. PR: #10–#12. *Compiled from records.*
- **R6b-1: option B.** `may_receive` searches every field in full for clear-text credentials and fails
  closed on attribution bounds that can hide a credential, an identifier or a verbatim copy (not on the
  fuzzy/cumulative bounds). Options: A–D as measured in `bench:may-receive`. Reason: the measured false-block
  cost. PR: #10. *Compiled from records.*
- **Configurable per-call attribution limits go to the backlog**, measured before any change. Reason: not
  recorded. PR: #10. *Compiled from records.*
- **Held-out sources approved:** MSB `c1d6a70`, MCPSecBench `7612c5a`, appsecco lab `47b7f20` (MIT,
  verbatim, parse-only). MCPTox stays out until its authors add a licence. Run rules: dedupe against
  dev/test, SHA-256 manifest, run once, Wilson intervals. PR: #11. *Compiled from records.*

## 2026-10-16

- **MSB prompt-injection items use the placement of its disabled insertion code** and are reported as their
  own subgroup, never pooled. Reason: the code is commented out at the pinned commit. PR: #11. *Compiled
  from records.*
- **README leads with the independent scanner result** (claimed 1/4, MSB PI 0/9), and the runtime trifecta
  block is presented as the core protection. Reason: the scanner does not generalise. PR: #11. *Compiled
  from records.*
- **Scanner generalisation (item 2b) comes after item 3**, built only from new dev examples of the five
  failure categories and measured on a different pre-registered set; `heldout-7` is never used to claim a
  fix. PR: #11. *Compiled from records.*
- **Runtime benchmark in two tiers:** decision-level replay for the numbers, and a black-box proxy only on
  the demo fixtures. Options: black box with loopback fixtures, or decision level. Reason: the
  safety-classifier history. PR: #12. *Compiled from records.*
- **Item 4 rules.** Ablate the split-secret partial leak with `may_receive_mode: context` and report it
  either way in the README limitations. Partial leaks are their own metric in every results table. PR:
  #14. *Compiled from records.*
- **Decision log, owner reviews and README roles.** This log is kept from now on. Every new review ends
  with an "Owner review" section (my verdict, what I changed or overrode, risks I accept); old reviews are
  not backfilled. The README states the roles precisely. Reason: decision provenance and authorship
  should be explicit. PR: #13.
- **Item 4: Layer 2 measured where it is designed to work.** Add a small pre-registered family of `from()`
  policy traces (benign and attack: deny when a recipient or URL comes from untrusted data; a declassify for
  trusted recipients). The report must say plainly that under the default config Layer 2 does not change
  trifecta decisions. Options: the existing suite alone, or adding policy traces. Reason: Layer 2 is designed
  to ground `from()` policies, and the suite has none, so without them the ablation would understate it. PR: #14.
- **Item 4: entropy `on_hit` measured on unclassified-source traces.** Options: add traces where the secret
  comes from a source with no confidentiality set (pre-registered), or report that `on_hit` has no effect on
  the existing suite. Reason: accepted the recommendation; there, `on_hit` would show no effect for a reason
  unrelated to entropy (every secret was already classified). PR: #14.
- **Item 4: "Layer 1 only" keeps the argument credential check, plus a row without it**; trifecta audit mode
  added as a configuration. Options: keep or drop the check, one row or two; include audit mode or not.
  Reason: the check is pattern detection, not attribution, and the extra row shows its own contribution.
  PR: #14.
- **Item 4: matcher ablation through an internal hook in `src/taint`**, on condition of a test proving that
  no configuration can reach it. Options: an internal constructor option, or filtering evidence in the bench.
  Reason: a matcher has to be turned off where it runs; the test keeps the switch out of the product.
  PR: #14.
- **No placeholders in drafts.** Owner review sections and every other draft are written in full from my
  messages, never with "[to fill]" fields; I edit them before merge. Options: not recorded. Reason: we both work
  on this project, so neither of us should lose context; Claude Code writes every draft in full in its role, I
  review and edit in mine, and each contribution stays distinct. PR: #14.
- **`init` follow-up scheduled (from the item-4 review, R7a-1).** `init` prompts users to classify each tool's
  confidentiality and warns about `may_receive_mode: context`'s false-block cost (unclassified outputs count as
  `internal`, so one such read blocks a `public`-bounded server). Options: not recorded. Reason (from my item-4 Owner
  review): R7a-1 is accepted because context mode is opt-in and documented, with this as its follow-up.
  Recorded in the DESIGN backlog. PR: #14.

## 2026-10-17

- **Item 5: the 1 MB cost is broken down with internal timing instrumentation.** Internal only, test-pinned
  like the ablation hook, and its own overhead measured. Options: timing hooks inside the gateway, or turning
  stages off through the configuration (which cannot isolate SDK validation or the transport hop). Reason: not
  stated beyond accepting the recommendation. PR: #15.
- **Item 5: GitHub-hosted `ubuntu-latest` through `workflow_dispatch` is the primary dataset.** The workflow
  file is shown to me before its first run, and run-to-run variance is reported honestly. Options: a
  GitHub-hosted runner (a shared VM, not truly quiet), a self-hosted runner (none exists), or the laptop alone.
  Reason: not stated beyond accepting the recommendation. PR: #15.
- **Item 5: eviction budgets 32 / 4 / 1 / 0.25 / 0.0625 MiB with benign filler, plus an adversarial-filler
  arm.** In that arm the untrusted source itself emits outputs sized to force eviction right before the attack
  step; attack success, partial leaks, false blocks and fail-closed denies are reported for it per budget.
  Options: benign filler only, or benign plus adversarial. Reason: adversarial filler is the real eviction
  threat. PR: #15.
- **Item 5: the laptop runs a reduced comparison set only** — 1 MB and the slash-heavy 128 KB case, ≥ 10
  launches each, plugged in, environment recorded; not the full matrix. Options: the full matrix on the laptop,
  or a reduced set. Reason: this machine has run out of memory before. PR: #15.
- **Item 5: fix the flaky e2e test in this PR.** `test/cli.e2e.test.ts` "approve pins definitions…" timed out
  at 30 s under full-suite load; raise its timeout or isolate it from that load, and log it in the review.
  Options: raise the timeout, or isolate the test. Reason: not stated. PR: #15.
- **Item 5: fix the decision-event growth first, in its own PR (option B).** Each event must still name the
  untrusted source(s) that drove it; the full list is stored once and referenced, not truncated; in-memory lists
  are bounded and counted against the index budget; the growth probe becomes a CI test; today's numbers are the
  "before" in the item-5 review. Options: A — run item 5 as is, fix later; B — fix first. Reason: not stated. PR: #17.
- **Item 5: `perf.yml` approved as shown, and added to `main` on its own** (option a), since GitHub dispatches
  only workflows on the default branch. It is dispatched against `7/pr5-latency` once #17 is merged and the
  branch updated. Options: (a) a workflow-only PR to `main`; (b) a push trigger on a dedicated branch. Reason: not
  stated. PR: #16.

## 2026-10-17 (after #15)

- **Item 5 Owner review verdict stands** ("Approved as a measurement PR"); #15 merged. Options and reason: not
  recorded beyond the approval. PR: #15.
- **R7p-3: fix before item 6, as its own PR, combining all three options.** Tier B gets a byte budget with
  oldest-first eviction; overflow marks the session degraded; deny-side `from()` rules fail closed in a degraded
  session. Rerun the F3 identifier-flood arm to show the 4/5 policy attacks are blocked, report the false-block
  cost, and update the README limitation. Options: any one of the three, or all. Reason: not stated. PR: the R7p-3 PR.
- **R7p-2: cap evidence per argument** to the strongest few entries plus a count; in the R7p-3 PR if small,
  otherwise right after it. Options: cap, or leave it bounded only by the index. Reason: not stated. PR: the R7p-3 PR.
