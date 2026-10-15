# Phase 6b review — entropy secrets, `may_receive`, exfiltration channels, corpus, PostHog

Scope: everything merged in 6b, as PRs #1–#8: PR 1 (tests for the 6a review's untested paths, two
fixes), PR 2 (entropy-based possible secrets, PostHog key rule, `bench:entropy`), PR 3 (`may_receive` and
the sink attack server), PR 4a (pre-push hook log), PR 4b (#8, exfiltration channels as decision-level
tests), PR 5 (scanner corpus), PR 5t (scanner tuning round), PR 5b (PostHog as a reference target). This
review is PR 6. It also carries two small fixes the owner asked for (tool-shadowing self-reference, base64
in URL path segments), each tuned only on new dev-split examples.

## What 6b adds

- **Possible secrets by entropy.** Random-looking tokens with no known format are redacted in the log
  and counted per output; by default they do not change the label (owner decision: entropy alone can't
  tell a key from an id). `on_hit: internal | secret` makes them escalate.
- **`may_receive`**: a per-server ceiling on the confidentiality of what tool-call arguments may carry,
  for every tool, which covers a server whose "read-only" tool is itself the sink. `evidence` mode
  (default, precise, bypassable) and `context` mode (sound, blunt).
- **Fail-closed fixes** from PR 1: audit-mode trifecta no longer skips a policy `ask`; `logging.on_failure:
  deny` now audits `prompts/get`, `resources/read`, `resources/(un)subscribe` and `completion/complete`
  before forwarding them.
- **Measurement**: scanner corpus of 248 real benign definitions plus third-party-derived poisoned
  examples; a tuning round for full-schema poisoning; `bench:entropy`; a static scan of PostHog's 1,121
  tools and an "untrusted event data" scenario.

## Measured (as of this PR)

| benchmark | held-out | notes |
|---|---|---|
| `bench:scanner` | TPR 100% (12/12), FPR 0% (0/132) | held-out split observed before round 5t: weaker evidence (below) |
| `bench:entropy` | FPR 9.2% (6/65), detection 78.0% | floor FPR ≤ 15%, detection ≥ 70%; every miss is a by-design kind |
| `bench:evasion` attribution | claimed 77/77 test, 81/81 dev | 15 new dev cases (this PR); false attribution 0/36 |
| `bench:evasion` scanner | claimed 49/49 test, 41/41 dev | unchanged |
| `bench:posthog` | 2 of 1,121 tools hidden (0.2%) | was 5 (0.4%); both remaining are MCPhantom false positives |
| `bench:policy` | see "Cost" | new case: 128 KB slash-joined base64-alphabet body (R6b-10) |

## The two fixes in this PR

**Tool shadowing read "this tool" as another tool.** The rule's name capture took `this` (and `the same
tool`) for a tool name; it was seen on PostHog's catalog (3 of the 5 hidden tools) and, per the owner,
not tuned on PostHog's data. Dev examples were written first (`bench/corpus/build-tuning-dev-r6.mjs`: 6
benign self-references in exactly the shapes the rule matches, 3 shadowing cases that must stay caught,
one of them with a self-reference *before* the real target, so a fix that stops at the first match
fails). The rule now checks every match and skips `this` / `same`.
Dev: TPR 100% → 100% (18/18), FPR 4.5% (6/134) → 0%. Held-out: 100% / 0% before and after.
PostHog catalog, reported only: hidden 5 → 2.

**Base64 in a URL path segment was not attributed** (the KNOWN GAP pinned by PR 4b). Cause: `/` is in
the standard base64 alphabet, so `…:9/i/<b64url>` forms one run that decodes to noise. The decoder now
tries each `/`-separated segment of a run that fails as a whole. Fixing it exposed a **wider defect than
the one pinned** (finding R6b-2): decoded text replaced the run in place and fused with its neighbours
(`d=` + token, URL + `.png`), so only pattern-detected secrets (AWS, GitHub) and e-mails survived; an
unformatted token or a URL base64-encoded in a **query parameter** was not attributed either. The PR 4b
test only used an AWS key, which is why "query parameters work" was believed. A decoded base64 segment is
now set apart by spaces. Dev cases written first (`bench:evasion`, pinned to `dev`: path segment with
extension, between segments, query parameter; × 5 identifier kinds): **3/15 → 15/15**. Held-out
attribution 77/77 unchanged; false attribution 0/36; no unclaimed case flipped; scanner, entropy and
PostHog results unchanged. The pinned test is flipped, plus a query-parameter test with an unformatted
token; each new test fails without the change. The first version of this fix was 17× slower on slash-joined runs and is now bounded (R6b-10, Cost).

## Findings

| # | Severity | Finding | Disposition |
|---|---|---|---|
| R6b-1 | **Medium (open, pinned)** | **`may_receive` evidence mode fails open past its own bounds.** The credential search covers the first 64 KiB of each of the first 512 argument leaves, and the check ignores the `degraded` flag attribution sets at the same bounds. A clear-text AWS key after 64 KiB of padding, or in the 513th leaf, reaches a server with `may_receive: internal` (probe and tests: `allow`, `attributionDegraded: true`). `secretRuleIn`'s comment ("the clear-text search always covers all of it") is not true for this caller. Context mode is unaffected. | Pinned as KNOWN GAP in `test/may-receive.test.ts`. Not fixed here (outside this PR's scope). Proposed: clear-text search over the whole leaf (cheap, as in `containsSecret`), and deny when a bounded server's decision is degraded. Owner decides. |
| R6b-2 | Medium (fixed here) | Decoded base64 inside a URL fused with its surroundings: unformatted tokens and URLs encoded in a query parameter or path segment were not attributed (Layer 1 still blocked under the trifecta). The DESIGN resume note said query parameters were covered; that held for format-detected secrets and e-mails only. | Fixed (above). Same splice remains for the hex, URL-escape, HTML-entity and `\u` decoders: not measured, listed under untested paths. |
| R6b-3 | Low (fixed here) | **Corpus count mislabelled.** Since round 5t, `scanner-bench.md` printed the 6 author-written dev examples as real definitions ("254 real"); PR 5's own title also said "254 real benign definitions". Real definitions: 248 (14 + 21 + 141 + 72); 254 was the benign *total* including 6 synthetic regressions. | The bench counts author-written examples separately (now "248 real, 12 author-written, 6 synthetic"). CHANGELOG wording ("254 benign tool definitions") was correct and is kept. |
| R6b-4 | Low (fixed here) | Tool-shadowing self-reference (above). | Fixed on dev examples; PostHog 5 → 2. |
| R6b-5 | Low (open) | The two remaining PostHog false positives: the shadowing rule takes an ordinary word as a tool name (`…using the download tool…`-shaped text, `error-tracking-symbol-sets-list`), and the redirect rule rates routing advice to another tool as medium (`mcp-connection-tools-list`). | Next scanner round, on new dev examples and a fresh held-out set (Phase 7). Not tuned on PostHog. |
| R6b-6 | Low (accepted, from PR 5t) | **Scanner held-out evidence is weak**: the held-out split had been observed before round 5t (the full-schema miss was seen in PR 5). This PR's fix did not use it, but it adds no new held-out evidence either. | Fresh held-out poisoned set, frozen before running, in Phase 7 (owner). |
| R6b-7 | Low (accepted, from PR 2) | Entropy: e-mail local parts flagged (4 of the 6 held-out false positives; seen on held-out, deliberately not fixed); human-chosen / low-entropy passwords undetected by design; ≈ 1.5% of random base64url tokens collide with the single-case type-prefix rule and are read as ids. | Next entropy round needs a fresh split. Default `record` means none of these change a label. |
| R6b-8 | Low (accepted, from PR 3) | `may_receive` evidence mode is bypassed by encodings neither the detectors nor attribution decode (decimal character codes; pinned). | By design; `context` mode closes it. `suggest` does not propose a `may_receive` value (deferred, owner: no server-level suggestion exists to build on). |
| R6b-9 | Low (accepted) | Possible secrets are counted in the first 1 MiB of an output (`MAX_ENTROPY_SCAN`). With `on_hit: internal | secret`, a random token after that does not escalate, and nothing is marked degraded. | Recorded; only matters with the non-default `on_hit`. Fold into the R6b-1 "degraded must restrict" decision. |
| R6b-10 | **Medium (fixed here, found in this PR)** | The first version of the base64 path-segment fix made decoding 17× slower on slash-joined runs (an exception per segment), enough to turn the 50 ms fail-closed policy deadline into false denies on large URL-heavy arguments. | Fixed and bounded (Cost). Pre-existing near-deadline cost of slash-heavy 128 KB bodies recorded for Phase 7. |

## Exfiltration channels: what is and isn't tested

The PR 4 plan was one small attack server per channel (query string, encoded query, path, split calls,
write outside the workspace, second egress tool). **Two attempts to build the server-backed scenarios
were stopped by a safety classifier** — the second after the owner had reshaped the work (a scripted
agent issuing tool calls directly with no injection prose, an inert placeholder marker, fragment-built
canaries, sinks enforcing loopback in code). **Owner decision: do not retry.** The channels are covered at
the decision level (`test/channels.decision.test.ts`: the session state is built directly and one
`tools/call` per channel goes to the gate). Server-level coverage of exfiltration stays the demo e2e,
the `may_receive` sink tests and the PostHog scenario. What this leaves unverified: that each channel's
request shape survives the real gateway path unchanged (namespacing, SDK validation, HTTP upstreams).

## Code paths NOT tested (required since the Phase-5 audit)

1. **Per-channel exfiltration through the real gateway and real servers** (above): decision level only.
2. **Hex, URL-escape, HTML-entity and `\u`-escape decoding inside URLs** for unformatted tokens and URLs:
   the R6b-2 splice fix covers base64 only; the others likely fuse the same way. Not measured.
3. `may_receive` with an **HTTP upstream**, with the **cumulative** matcher (a credential split across
   calls to a bounded server), and the `mcphantom trace` rendering of a `may_receive` denial.
4. `may_receive` past its leaf and size bounds: now pinned as a gap (R6b-1), not tested as fixed.
5. `secrets.entropy.redact: false` **through the config** into the store: the `Redactor` option is tested
   in isolation and the test harness mirrors the `run` wiring, but `cmdRun`'s line is not exercised.
6. Possible-secret counting past `MAX_ENTROPY_SCAN` (1 MiB), and in `structuredContent`-only outputs.
7. `resources/unsubscribe` audited-before-forwarding: shares the `subscribe` code path, which is tested.
8. The importers and generators (`import-posthog.mjs`, `import-benign-thirdparty.mjs`, `build-*.mjs`)
   have no tests; their outputs are committed and were reviewed by diff.
9. **PostHog's real MCP server** has never been run: the scenario uses a fixture with PostHog's
   `execute-sql` definition and response envelope (Phase 7: the real server against a local mock
   backend). Input schemas of 1,120 of the 1,121 tools are not published and were not scanned.
10. The pre-push hook's log path was exercised by its test on Windows locally; the hook itself is not
    run in CI (CI is the backstop it guards).
11. Development and local runs were on Windows 11 only; Linux/macOS are covered by CI.

## Process incidents

- **gitleaks false positive in synthetic data (PR 2).** The generic-api-key rule fired on a synthetic
  corpus line (a keyword next to a random value) and failed CI. Force pushes are denied on `main`, so the
  finding is suppressed by one commented fingerprint in `.gitleaksignore` (kept, owner). Process change:
  gitleaks (the CI-pinned version) runs locally before pushing corpus or fixture data.
- **A lost pre-push failure** (6b, cause unconfirmed): a push was blocked and the failing output was not
  visible. PR 4a: the hook keeps its full output in `.git/mcphantom-pre-push.log` and prints the path.
- **Safety-classifier stops (PR 4)**: above; owner reshaped the work, then decided against retrying.
- **Held-out observed before tuning (PR 5 → 5t)**: the scanner held-out miss was seen in PR 5 and then
  tuned in 5t on dev examples; the after-number is reported as weaker evidence.
- **`bench:policy` deadline denies on the development laptop** are machine load: the same denies appear
  on PR 1's code under load, and none on a quiet run (cost section).
- **This PR**: the decoder fix passed every benchmark the conventions require and still carried a 17×
  slowdown (R6b-10) — found only by timing the decoder on an input class no benchmark had. Lesson: a
  matcher change needs a benchmark case for the input shape it changes. Also, a Python patch lost an escaped quote and a later edit declared a helper twice; both broke
  a bench run and were caught before any commit (the bench crashed rather than reporting).

## Cost

**The base64 fix nearly shipped a deadline regression (R6b-10, found and fixed in this PR).** The first
version tried every `/`-separated segment through a strict UTF-8 decoder that *throws* on invalid input,
so each non-base64 segment cost an exception. Measured directly on the decoder (128 KiB, median of 15):
a hostile slash-joined run 38.9 → 657 ms, ordinary URL-dense text 31.7 → 246 ms, prose unchanged.
`bench:policy` did not show it, because none of its inputs had slash-joined runs. Fixes: UTF-8 is
validated without throwing (`isUtf8`); only segments mixing upper and lower case are tried (base64 of
printable text practically always does; ordinary path words do not); and at most 256 segment tries per
`decodeVariants` call, past which the result is reported `truncated` (the decision is marked degraded;
nothing is skipped silently). A new `bench:policy` case covers the input class.

After, interleaved old/new on the decoder with the policy path's limits (32 KiB, `wholeOn: tokens`,
median of 40 alternating runs): slash-joined mixed-case 10.3 → 12.4 ms (budget hit, reported),
single-case 10.3 → 11.7 ms, URL-dense 12.9 → 15.7 ms, 128 KiB prose 44.2 → 46.5 ms. **Bounded at about
+3 ms per decode.**

**Pre-existing, not caused by this PR:** with the *original* decoder, the new slash-joined case already
sits near the 50 ms policy deadline on this laptop (policy p50 31.6–34.1 ms; 10/300 and 17/300 deadline
denies in two runs) — fail-closed false denies for large slash-heavy arguments. Full `bench:policy` runs
during this PR were not quiet enough to compare old and new end to end (one run includes a ~40-minute
sample from a machine suspend); the quiet run's other cases matched 6a's numbers with 0 deadline denies.
Phase 7's latency work must measure this case on a quiet Linux runner with repeated launches.

## Test evidence

`npm run check` (lint, typecheck, build, tests) on Windows 11: **464/464 tests** across 31 files. New in
this PR: shadowing self-reference and self-reference-before-target (`scanner.test.ts`); base64url in a
path segment with an extension, between segments and in a query parameter, an ordinary path left
alone, and the segment budget reporting truncation (`text.test.ts`); the flipped path-segment test and
an unformatted-token query-parameter test (`channels.decision.test.ts`); the R6b-1 KNOWN GAP, two cases
(`may-receive.test.ts`). Each fix's tests were run against the code without the fix and failed.
`bench:scanner`, `bench:evasion`, `bench:posthog`, `bench:entropy` and `bench:policy` rerun after the last
decoder change; their result files are committed (`bench:entropy` output unchanged; `bench:policy`
prints only, so its numbers are in the Cost section). gitleaks 8.30.1 (checksum verified)
over the working tree: no leaks.
