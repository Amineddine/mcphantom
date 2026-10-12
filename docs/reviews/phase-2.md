# Phase 2 hostile review — vertical slice (trifecta + exact/normalized matching + demo)

Scope: the taint engine (labels, context label, trifecta invariant), the provenance index (exact,
normalized, Tier A/B with eviction), secret detection as a taint source, the gateway integration, the
three demo servers, the deterministic injected agent, the side-by-side demo, and `mcphantom trace`.

## What Phase 2 adds

MCPhantom now **blocks** one class of attack: the lethal trifecta. When a session has taken in both
untrusted content and secret data, an `egress`/`exec` tool call is denied by default. The agent gets a
tool error naming the decision id; `mcphantom trace --last` shows the Layer-1 sources and the Layer-2
evidence. The deterministic demo proves it end-to-end with the attacker collector's log as the oracle:
unprotected, the canary AWS key reaches the attacker; through MCPhantom, the egress call is blocked and
nothing arrives.

This is still narrow. Poisoned tool *descriptions* and rug-pulls are not addressed (Phases 3–4). Only
exact/normalized provenance exists; encoded and paraphrased payloads are not attributed (Phase 6).

## How the attack and oracle avoid grading themselves

The injected agent is deterministic — it does not call an LLM — so the Tier-1 result measures the
*defense*, not a model's willingness to obey. Whether a real model obeys is a separate, live question
measured through Claude Code (Phase 9; not claimed here). The oracle is the attacker collector's own
HTTP request log, which neither the agent nor MCPhantom can write to, so a pass cannot be faked by the
component under test.

## Findings

| # | Severity | Finding | Disposition |
|---|---|---|---|
| A1 | **Medium (limitation)** | A tool classified `write` is **not** caught by the trifecta invariant — only `egress`/`exec` are treated as exfiltration channels. A `write` whose destination is attacker-controlled (a write to a remote path, or a local write a second untrusted-reachable tool later exposes) is exfiltration the invariant misses. | **Documented, test-pinned** (`taint.test.ts` A1). Consistent with the effect model in DESIGN.md §3. Unknown tools default to `egress`, so this requires the user to have *explicitly* labelled the tool `write`. Per-destination rules (deny a write whose path argument is attributed to untrusted content) belong to the policy engine (Phase 4); doing a half-version now would be the kind of unmeasured claim this project forbids. |
| A2 | **High (fixed)** | Running all test files fully parallel starved CPU on this laptop, so child MCP servers exceeded their 30 s startup timeout and ~9 tests failed intermittently. A flaky security test suite is a real defect: it trains reviewers to ignore red. | Fixed: `maxForks: 2`. Full suite is green and stable. Also the real reason the first CI needed the ACL and install fixes — small runners behave like this laptop. |
| A3 | Strength (test-pinned) | An **error** result from an untrusted server still taints: injections hide in error text, and a naive engine that only reads successful results would miss them. | `taint.test.ts` A3. |
| A4 | Strength (test-pinned) | A **prompt** fetched from an untrusted server taints: `prompts/get` is an injection channel as much as `tools/call`. | A4. |
| A5 | Strength (test-pinned) | An **image-only** output from an untrusted server taints by source, even though its bytes are not inspected (documented limitation of content scanning, not of labelling). | A5. |

## Known weaknesses carried forward (tracked, not hidden)

1. **Over-tainting across conversations.** One `TaintEngine` lives per downstream connection. MCPhantom
   cannot see conversation boundaries inside a client, so once a session has read untrusted + secret
   data, egress stays blocked for the life of the connection. This is sound (no missed exfiltration)
   but costs false blocks. Measured cost and a reset mechanism are Phase 7+.
2. **Encoding and paraphrase evade *attribution*, not the block.** base64/hex/split secrets are not
   attributed by the exact/normalized matchers (pinned as a KNOWN GAP test). Layer 1 still blocks the
   call, so attribution loss degrades the *explanation*, not the *protection*. Decoders are Phase 6.
3. **Homoglyph folding is not done.** `normalize` folds NFKC, zero-width and case, but not cross-script
   confusables (Cyrillic «а» vs Latin «a»). A disguised identifier may miss Layer-2 attribution (again,
   not the block). Confusables table is Phase 6.
4. **Secret detection is pattern-based.** The context only becomes `secret` if a detector or a
   `secret` classification fires. A high-entropy value with no known format and no keyword is not
   detected (entropy detector: Phase 6). A conservative user classifies sensitive tools `secret`.
5. **Resource reads are classified by server default only.** No per-URI classification yet.
6. **The demo's deterministic agent is not a model.** It proves the mechanism, not that models fall for
   this specific page. The live-model rate is explicitly deferred and will be reported as a measured
   number, not asserted.

## Test evidence

`npm run check` on Windows 11 / Node 22: lint + typecheck + build clean, **136/136 tests** across 11
files (adds taint engine/provenance/labels, the demo e2e with the collector oracle, and `trace`). Dist
e2e 4/4. `npm run demo` shows the contrast and exits 0 only when the unprotected arm leaked and the
protected arm did not.
