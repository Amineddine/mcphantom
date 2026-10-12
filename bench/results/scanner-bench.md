# Tier-1 static scanner benchmark

Generated 2026-10-12T22:52:15.339Z · scanner block threshold: medium.

Corpus: 14 malicious (synthetic, hand-labelled) + 35 benign (real tool definitions).
Benign sources: @modelcontextprotocol/server-filesystem@2026.8.31, @modelcontextprotocol/server-everything@2025.8.18, @modelcontextprotocol/server-memory@2025.8.4, @modelcontextprotocol/server-sequential-thinking@2025.7.1.
Split is frozen: `test` is held out and never tuned against; detectors are tuned only on `dev`.

| split | malicious | benign | TPR (recall) | FPR | precision |
|---|---|---|---|---|---|
| test (held-out) | 7 | 21 | 100.0% | 0.0% | 100.0% |
| dev | 7 | 14 | 100.0% | 0.0% | 100.0% |
| all | 14 | 35 | 100.0% | 0.0% | 100.0% |

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
