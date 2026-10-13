# Tier-1 static scanner benchmark

Generated 2026-10-13T00:04:54.170Z · scanner block threshold: medium.

Corpus: 14 malicious (synthetic, hand-labelled) + 41 benign (35 real tool definitions, 6 synthetic false-positive regressions).
Benign sources: @modelcontextprotocol/server-filesystem@2026.8.31, @modelcontextprotocol/server-everything@2025.8.18, @modelcontextprotocol/server-memory@2025.8.4, @modelcontextprotocol/server-sequential-thinking@2025.7.1.
Split is frozen: `test` is held out and never tuned against; detectors are tuned only on `dev`.

| split | malicious | benign | TPR (recall) | FPR | precision |
|---|---|---|---|---|---|
| test (held-out) | 7 | 23 | 100.0% | 0.0% | 100.0% |
| dev | 7 | 18 | 100.0% | 0.0% | 100.0% |
| all | 14 | 41 | 100.0% | 0.0% | 100.0% |

## Detection by category (all items)

| category | caught / total |
|---|---|
| hidden-unicode | 4 / 4 |
| embedded-instruction | 6 / 6 |
| exfiltration-hint | 2 / 2 |
| tool-shadowing | 2 / 2 |

Caveat: this corpus is small and the malicious set is author-written, so these numbers bound nothing
about novel attacks. They are a regression signal and a floor. The adversarial-evasion suite (Phase 6)
and third-party payloads strengthen it.
