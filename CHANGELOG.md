# Changelog

## Unreleased

### Added

- **Fresh third-party held-out set for the scanner** (`npm run bench:heldout`, run once;
  `docs/reviews/phase-7-heldout.md`). 88 poisoned definitions from MSB and MCPSecBench (MIT, verbatim),
  pre-registered and frozen with a SHA-256 manifest before the scanner saw them. **The scanner caught 1
  of 4 claimed description injections and 0 of 9 MSB prompt injections; only 1 of 88 items raised any
  finding.** It does not recognise common third-party injection wording; the README says so.

- **Entropy-based possible-secret detection.** Random-looking tokens with no known format are redacted
  in the event log and counted on each ingested output (`mcphantom trace` shows them). By default they
  do **not** change the session label, since they can't be told apart from random ids;
  `secrets.entropy.on_hit: internal | secret` makes them escalate. Identifier-shaped values (hex,
  UUIDs, digests, type-prefixed ids, values of id-named fields) are recorded only. Measured with
  `npm run bench:entropy` (in CI, held-out split): 9.2% of benign outputs still contain such a token,
  so escalating causes false blocks; detection 78.0% of generated secrets.
- **Per-server `may_receive`.** Bounds the confidentiality of what a server may receive in tool-call
  arguments, for every tool (not only egress ones), so a server whose "read-only" tool keeps what it is
  sent is covered. `evidence` mode (default) blocks credentials and data Layer 2 attributes to more
  confidential outputs; `context` mode blocks whenever the session holds such data. Unset: no change.
- **Scanner benchmark on a realistic corpus.** 254 benign tool definitions (213 new: GitHub's MCP
  server, MIT, and Microsoft's Playwright MCP server, Apache-2.0; licences in NOTICE) and 5 poisoned
  definitions rewritten from published attacks (Invariant Labs, CyberArk, Trail of Bits), all in the
  held-out split. Held-out TPR 91.7%, FPR 0.8%; the miss (a payload in a parameter name) and both false
  positives are listed in `bench/results/scanner-bench.md`.
- **Scanner reads the whole schema.** Parameter names, `required` entries, unknown keywords and strings
  nested in defaults are scanned as well as descriptions (full-schema poisoning); hints found in those
  structural fields hide the tool, and a field that asks for sensitive data is flagged. "Always call
  this tool" is no longer read as an instruction to call another tool (it hid two GitHub tools).
  Held-out: TPR 91.7% → 100%, FPR 0.8% → 0% — on a split already observed before tuning.
- **PostHog MCP server as a reference target** (`docs/posthog.md`). Static scan of PostHog's
  published tool catalog (`npm run bench:posthog`): 2 of 1,121 tools would be hidden (5 before the
  tool-shadowing fix below), all MCPhantom false positives. A fixture-based "untrusted event data" scenario in CI: `execute-sql` output is
  labelled untrusted, a later exfiltration is blocked, and a write back into PostHog is stopped by a
  policy rule. A generic MCP risk, not a PostHog vulnerability; no PostHog service was contacted.
- **PostHog API keys** (`phx_`, `phs_`, `pha_`, `phr_`, `phh_`) are detected as secrets. Project tokens
  (`phc_`) are public by design and are not.

### Fixed

- **A policy `ask` was skipped in trifecta audit mode.** With `taint.trifecta: log`, a call that tripped
  the invariant was allowed without asking, even when a policy rule required confirmation. The `ask`
  now applies; the decision's reason also records the audited invariant. The default
  (`taint.trifecta: deny`) was not affected.
- **`logging.on_failure: deny` now holds before forwarding.** `prompts/get`, `resources/read`,
  `resources/subscribe` and `completion/complete` were sent upstream before anything was audited; only
  the response was withheld. They are now recorded first (`request` event, outcome `forwarding`), and
  not sent if that write fails. The default (`warn`) was not affected beyond the extra event.
- **Base64 inside a URL was attributed only for known-format secrets and e-mail addresses.** An
  unformatted token or a URL, base64-encoded into a query parameter or a path segment
  (`/i/<base64>.png`), was not traced back to the output it came from; the trifecta invariant still
  blocked, but `may_receive` evidence mode and `from()` rules did not see it. Decoded segments are now
  kept apart from the surrounding URL, and path segments are decoded one by one.
- **"Before calling this tool…" hid tools as shadowing.** The tool-shadowing rule read "this tool" and
  "the same tool" as the name of another tool. Found on PostHog's catalog (3 tools), fixed on new
  author-written examples.

- **`may_receive` evidence mode stopped looking after 64 KiB of an argument or 512 argument fields.** A
  credential sent past either bound was not blocked. Every field is now searched in full, and a call
  that is too big to check (or follows an output attribution lost track of) is denied when the session
  holds data above the server's bound; the reason says which bound and how to proceed. Edited copies in
  fields over 8 KiB and splits more than 16 KiB apart are not covered in evidence mode (see Known
  limitations; `npm run bench:may-receive` shows the false-block cost of the alternatives).

## 0.1.0 (2026-10-13)

First public release. Early software: read
[Known limitations and bypasses](README.md#known-limitations-and-bypasses) before relying on it. Not on
npm yet (planned for v1); install from a checkout or from the tarball attached to the GitHub release.

### What's in it

- **Gateway core (Phase 1).** A single `mcphantom` entry in front of your MCP servers. Downstream is
  stdio; upstream is stdio or Streamable HTTP. Tools are namespaced `<server>__<tool>`. Every method has
  an explicit handler, unknown methods are rejected, and failures close (deny). `sampling/createMessage`
  is denied by default, and servers get a minimal environment. Listings and HTTP bodies are byte-bounded
  and redirects stay same-origin. A URI claimed by two servers is unroutable, which prevents resource
  shadowing. There is a redacted SQLite event log with retention, and MCPhantom's own files are
  restricted to your user (POSIX modes, Windows single-SID ACLs). CLI: `init` (Claude Code, Claude
  Desktop, Cursor; shows a diff and keeps a backup), `uninstall`, `run`, `doctor`.
- **Taint tracking and the trifecta invariant (Phase 2).** Integrity and confidentiality labels, and a
  per-connection context label that only rises. An egress/exec call while the context is both untrusted
  and secret is denied; a `write` outside its workspace counts as egress. Exact and normalized argument
  provenance, with a bounded two-tier index. Detected secrets count as a taint source. `mcphantom trace`.
  Deterministic side-by-side demo (`npm run demo`).
- **Static scanner (Phase 3).** Hidden Unicode, embedded instructions, tool shadowing, and
  exfiltration/credential hints in tools, prompts and server `instructions`. Flagged items are hidden at
  list time. Tier-1 benchmark (`npm run bench:scanner`).
- **Rug-pull detection (Phase 4).** Canonical-JSON SHA-256 pins in an HMAC-signed lockfile
  (`mcphantom approve`, `mcphantom lock diff`). Changed or new definitions are hidden, including after
  `list_changed`. A tampered or malformed lockfile stops startup.
- **Policy engine (Phase 5).** Per-tool CEL rules (deny > ask > allow) with `from`, `containsSecret`,
  `glob`, `within`; named, audited `declassify` exceptions; `ask` via MCP elicitation, otherwise deny;
  fail-closed on absent arguments, CEL errors and the evaluation deadline. `policy lint/test/explain`,
  `suggest`.
- **Layer-2 deepening (Phase 6a).** A shared normalize/decode pipeline (Unicode confusables 16.0.0,
  despacing, bounded decoders) feeding the decoded, fuzzy (winnowing) and cumulative (split across calls)
  matchers. The scanner runs through the same pipeline. Allow rules and declassify count only
  deterministic evidence. `logging.on_failure: deny` and `resources.unrouted: deny`. Adversarial-evasion
  benchmark (`npm run bench:evasion`) in CI.

### Measured (deterministic, author-written suites; commands in the README)

- Scanner, held-out split: TPR 100%, FPR 0% (14 poisoned + 41 benign definitions, a small corpus).
- Evasion: 143/143 claimed attribution transformations caught, 0/36 false attributions, 90/90 claimed
  scanner disguises caught. Every evasion that still succeeds is listed in
  `bench/results/evasion-bench.md`.
- Decision latency p50: 1.6 ms (small arguments), 86 ms (128 KB body), on an i5-8250U laptop.

### Known limitations

Client-native tools are not covered. MCPhantom is not a sandbox. Same-user tampering is mitigated, not
prevented. Resources are not pinned. Secret detection has no entropy detector yet. Per-server
`may_receive` is not implemented. `ask` without elicitation is a deny. Full list in the README.

### Reviews

Every phase ended with a hostile self-review, which also lists the code paths that are not tested:
[1](docs/reviews/phase-1.md) · [2](docs/reviews/phase-2.md) · [3](docs/reviews/phase-3.md) ·
[4](docs/reviews/phase-4.md) · [5](docs/reviews/phase-5.md) · [6a](docs/reviews/phase-6a.md) ·
[6.5](docs/reviews/phase-6.5.md).
