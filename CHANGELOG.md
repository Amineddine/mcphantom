# Changelog

## 0.1.0 (unreleased)

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
