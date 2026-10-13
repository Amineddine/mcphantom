# Phase 6a review — Layer-2 matchers, shared pipeline, evasion benchmark

Scope: the carried fail-closed fixes done first (audit-log deny mode, whole-evaluation policy deadline,
unrouted resources), the shared text pipeline (`src/text/`: confusables folding, `despace`, bounded
decoders), the `decoded`, `fuzzy` and `cumulative` matchers (`src/taint/provenance.ts`, `fuzzy.ts`,
`cumulative.ts`), the scanner running through the same pipeline, and `bench:evasion`. Phase 6 was split
by the owner; 6b (entropy secrets, exfiltration attack servers, corpus ≥ 200) is not covered here.

## What 6a adds

- **Layer 2 sees through disguises.** An identifier that has to cross the LLM boundary exactly (a key,
  a token, an attacker URL or address) is attributed to the output it came from when the argument
  carries it encoded (base64, hex, URL, HTML entities, `\u`/`\x` escapes, rot13, reversal, separator
  spelling, and chains of these up to depth 3), disguised (fullwidth, zero-width, cross-script
  look-alikes), split across fields of one call or across calls to the same tool, or when the *output*
  carried it encoded (a base64 Kubernetes secret, a reversed URL in an injected page). Prose copied with
  light edits or reordering is attributed by winnowing fingerprints. Evidence records the matcher, the
  decode chain on either side, the fuzzy score, and how many earlier calls were joined.
- **The scanner runs on the same pipeline**, closing the Phase-3 bypasses B1 (homoglyphs), B3 (base64)
  and B4 (letter spacing) in one place, plus fullwidth, hex, URL, entities, rot13 and reversal.
- **Fail-closed items carried from earlier phases**: `logging.on_failure: deny` (default `warn`), the
  policy deadline covering the whole evaluation, and unrouted resource URIs denied by default.

## Measured

`npm run bench:evasion` (deterministic, model-free, in CI; full table and every successful evasion in
`bench/results/evasion-bench.md`):

| suite | claimed caught | unclaimed (expected bypasses) caught |
|---|---|---|
| runtime attribution, 5 identifier kinds × 33 transformations + prose edits | **143/143** | 0/39 |
| static scanner, 6 payloads × 20 disguises | **90/90** | 7/30 (residual raw signals) |
| false attribution, 36 unrelated benign pairs | — | **0/36** |

`npm run bench:scanner`: held-out TPR 100%, FPR 0% (unchanged), and no disguise-derived finding on any of
the 41 benign definitions.

**Methodology honesty.** The suite is author-written, like the scanner corpus; it measures the
transformations we thought of, not novel ones. "Claimed" was decided by the design before the run; the
first run missed 14 claimed cases, which exposed real defects (below) — they were fixed in code, not by
re-labelling, with one exception, stated: a random token carried *reversed in an output* was first
re-labelled unclaimed, then found to be caught after all (the argument's reversal reproduces the
indexed reversed token) and restored to claimed. Two unclaimed cases (pieces out of order, pieces across
two tools) were "caught" only because halves of a 40-character token are long enough for the verbatim
copy check; the suite now uses 8-character pieces for those and keeps the halves version as a separate,
claimed copy-match case, so the table does not overstate reassembly.

**Cost (the price of this phase, measured — `bench/results/policy-bench.md`, i5-8250U laptop):**

| | before 6a (p50 / p95) | after 6a (p50 / p95) |
|---|---|---|
| decision, small arguments | 0.35 / 0.73 ms | 1.64 / 3.17 ms |
| decision, 128 KB body | 28.9 / 44.2 ms | 86.3 / 99.1 ms |
| policy evaluation alone, 128 KB body | 2.1 / 3.7 ms | 17.8 / 23.6 ms (`containsSecret` decodes) |

Ingesting an output now also decodes its first 128 KiB (≈ +20 ms for a 64 KiB prose output) and
fingerprints it (≈ 5 ms per 64 KiB). The larger, pre-existing ingest cost is identifier extraction on
URL-dense text (≈ 450 ms/MB) — tracked for the Phase-7 latency work, not changed here.

## Findings

| # | Severity | Finding | Disposition |
|---|---|---|---|
| R6a-1 | **High (fixed)** | **Fuzzy evidence could ground an allow**, contradicting owner decision 3: `from()` used all Layer-2 evidence, so a declassify `when: 'from(arg.to, "trusted")'` was satisfiable by a fuzzy similarity and would lift the trifecta invariant. | `from()` in an `allow` rule or a declassify condition now counts only deterministic evidence (exact, normalized, decoded); deny/ask rules still use every matcher. Cumulative evidence never reaches `from()` (it attributes one value, no sink). Test proven to fail without the fix. |
| R6a-2 | **High (fixed)** | **List-time DoS introduced by this phase**: disguise-undone scanning of a hostile definition (2 MB of base64 across 2000 property descriptions) took ~3.5 s per tool. | Per-definition bound (64 KiB of model-visible text); larger definitions are reported `unscannable` (medium → hidden by default, fail-closed). Now ~0.2 s (the raw scan), ≤ ~125 ms under the bound. |
| R6a-3 | **High (fixed, during the build)** | **`containsSecret` decoding a 128 KB body blew the 50 ms deadline**: 296/300 legitimate calls denied in the benchmark. | Decoding in `containsSecret` covers the first 32 KiB of a value (clear-text search still covers all of it), and rot13/reversal apply to whitespace-free tokens for attribution. 0/300 now. |
| R6a-4 | Medium (fixed) | Separator spelling broke on punctuation inside the value (`ghp_`, `https://`, `@`, `<system>`) and on two-letter words — found by the evasion suite (12 of the 14 first-run misses). | `despace` rewritten: consistent separator per run, any non-space element, parity parsing for whitespace-bounded runs (the separator may be an element), two-letter words joined only next to a word gap. FP guards unchanged. |
| R6a-5 | Medium (fixed) | Random tokens were skipped under rot13/reversal on the *argument* side too, so a reversed or rot13'd API token escaped attribution. | Argument side matches every kind under every decoder; the output side still skips random tokens under those two (Tier B size). |
| R6a-6 | Medium (fixed) | A deadline-bounded policy is only meaningful if evaluation is cheap: `run()` re-parsed and re-planned every expression on every call. | Expressions are planned once per engine (5× faster on small calls). |
| R6a-7 | Low (accepted) | Over-tainting grows: a known-format secret found *base64-decoded* in an output (Kubernetes secret, `.env` dump) now makes the context `secret`. An untrusted page can do the same with a fake key — as it already could in clear text since Phase 2. | Intended (Layer 1 is the sound layer); only realistic stored-secret encodings escalate, never rot13/reversal. The over-tainting cost is a Phase-7 measurement. |
| R6a-8 | Low (accepted) | A 4000-field call's policy evaluation peaks near the 50 ms deadline on this laptop (max 43–50 ms across runs); on a slower runner such a call can be denied. | Fail-closed by design; documented. |

## Published bypasses (pinned by tests and listed in the benchmark)

Attribution: encodings not decoded (decimal character codes, caesar shifts, NATO spelling, junk
letters interleaved, groups separated by multi-character gaps); pieces sent out of order or to
different tools; paraphrase. Scanner: filler words inside an instruction, leetspeak, translation,
decimal character codes, base64 split across properties (caught only when the split happens to fall on
a 4-character boundary). Every one of these still faces Layer 1, which is content-blind.

## Code paths NOT tested (required since the Phase-5 audit)

1. `logging.on_failure: deny` for `prompts/get`, `completion/complete`, `resources/subscribe`, and the
   relayed server→client requests (elicitation, sampling, roots). Only `tools/call` (decision and
   result) and `resources/read` are exercised.
2. The policy deadline triggered by genuinely slow CEL evaluation; tests inject a clock.
3. `scripts/gen-confusables.mjs` has no test; the committed table was generated once from the pinned
   16.0.0 file and spot-checked (version, ASCII-only targets, specific mappings).
4. Output decode truncation for a *trusted, internal* output (only an untrusted one is tested), and
   `containsSecret` past its 32 KiB decode bound.
5. Fuzzy fingerprints evicted together with Tier-A text (eviction of fingerprint bytes is accounted, but
   no test asserts a fuzzy match disappears after eviction).
6. Cumulative matcher: an `ask`-approved call recorded as sent (gateway path), sink LRU eviction
   affecting a real decision, the exact 15-minute window boundary, and HTTP upstreams.
7. Disguise-undone scanning of **prompts** and server **instructions** (only tools are tested), and the
   `unscannable` path for them.
8. `mcphantom trace` rendering of the new evidence fields (chain, score, joined calls) is not asserted.
9. Development and local runs were on Windows 11 only; Linux/macOS are covered by CI.

## Test evidence

`npm run check`: lint + typecheck + build clean, **331/331 tests** across 25 files (adds `text`,
`fuzzy`, `cumulative`, `fail-closed` suites and extends `taint`, `policy`, `scanner`).
`bench:evasion`, `bench:scanner` and `bench:policy` rerun after the last change; results committed.
