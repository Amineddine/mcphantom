# Phase 3 hostile review — static scanner + list-time filtering

Scope: the text extractor (`src/scanner/extract.ts`), the detectors (`detectors.ts`), the scan/verdict
layer (`scan.ts`), the gateway list-time integration, the poisoned fixture server, the benign + malicious
corpora, and the Tier-1 static benchmark.

## What Phase 3 adds

Every tool and prompt is scanned before it is shown to the client; the server's `instructions` block is
scanned the same way. A finding at or above the configured severity (default `medium`) **hides** the
tool from `tools/list` (so it never enters the model's context and cannot be called), or in `warn` mode
keeps it but records the findings. Detected categories: hidden/invisible Unicode (tag chars, bidi,
zero-width, private-use), instructions aimed at the model (imperatives, fake `<system>` blocks, role
markers), tool shadowing (redefining another tool), and exfiltration / sensitive-file hints, with
co-occurring hints combined into a high-severity finding.

## Measured, with a frozen split

`npm run bench:scanner` scores the detectors against 35 **real** tool definitions from four official MCP
servers (benign) and 14 synthetic poisoned tools (malicious), each with a frozen `dev`/`test` split.
Detectors are tuned only on `dev`; `test` is held out. Current held-out result: **TPR 100%, FPR 0%,
precision 100%** — on a *small, author-written* malicious set, so it bounds nothing about novel attacks
and the report says so. CI fails if the held-out TPR drops below 90% or FPR rises above 10%.

**Methodology honesty:** the detectors were written before the corpus was split. One false negative
surfaced on `dev` during development (an imperative that directs calling another tool); I generalised
the rule from that `dev` example, and the `test` split then independently confirmed the fix — I did not
edit detectors to match a `test` item. The two FN categories at authoring time are recorded in the
benchmark JSON.

## Findings

| # | Severity | Finding | Disposition |
|---|---|---|---|
| S1 | Strength | Invisible-character smuggling — Unicode tag chars (the U+E00xx "ASCII smuggling" block), bidi overrides, zero-width — is caught at `high` with ~0 false positives, including a single tag char buried in a long benign description. This is the most reliable injection vector, so catching it matters most. | Verified; `scanner.test.ts`. |
| S2 | Strength | Findings never re-emit the payload: evidence excerpts strip control/format characters, and invisible chars are reported by codepoint. The scanner cannot itself become an injection channel into logs or the dashboard. | Pinned by a test. |
| S3 | Strength | The scanner is wired at **list time**, so a flagged tool is never offered to the model and has no route to call — closing the window that a call-time-only check would leave open. | `scanner.gateway.test.ts`. |
| B1 | **Known bypass** | **Homoglyph** substitution (Cyrillic look-alikes for Latin letters) evades the instruction patterns. | Documented; pinned as a MISS test. Confusables folding is Phase 6. |
| B2 | **Known bypass** | An instruction **split across two property descriptions** (each benign alone) is not caught — the scanner does not concatenate spans, to avoid false positives. | Documented; MISS test. |
| B3 | **Known bypass** | **base64 / encoded** instruction text in a description is not decoded, so it is not matched. | Documented; MISS test. Decoders are Phase 6. |
| B4 | **Known bypass** | **Letter-spacing** ("i g n o r e") evades word-boundary patterns. | Documented; MISS test. |

**Why the bypasses are acceptable for this layer, stated plainly:** the static scanner is
defence-in-depth, not the last line. Every B-class bypass produces a payload whose *purpose* is to make
the agent exfiltrate; at runtime the trifecta invariant (Phase 2, content-blind Layer 1) still blocks
the egress regardless of whether the description was scanned. The scanner's job is to stop the poison
from entering the model's context when it can recognise it, not to be a complete prompt-injection
classifier — which is an unsolved problem and would be dishonest to claim.

## Other limitations carried forward

1. **Small, author-written malicious corpus.** 100%/0% is a floor and a regression signal, not a
   capability claim. Phase 6 adds the adversarial-evasion suite and third-party payloads (Invariant
   Labs and others, licence permitting) to the corpus.
2. **No semantic understanding.** The detectors are patterns. A paraphrased instruction with no trigger
   word, no imperative and no invisible characters is not caught (and again is a runtime concern).
3. **Excessive-permission detection is not implemented yet.** The category exists in the taxonomy but
   there is no detector that cross-checks a `readOnlyHint: true` tool against a write-sounding
   name/description. Deferred; it needs the annotation handling that pairs with the policy engine.
4. **Scanning is per-definition, stateless.** Detecting that a *previously clean* tool changed into a
   poisoned one is rug-pull detection — Phase 4.

## Test evidence

`npm run check`: lint + typecheck + build clean, **171/171 tests** across 14 files (adds
`scanner.test.ts` incl. FP guards and pinned bypasses, `scanner.gateway.test.ts`). ReDoS timing: all
detectors stay under ~150 ms on ~1 MB adversarial inputs. `npm run bench:scanner` passes its held-out
floor and is enforced in CI.
