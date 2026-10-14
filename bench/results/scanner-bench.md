# Tier-1 static scanner benchmark

Generated 2026-10-14T03:15:42.555Z · scanner block threshold: medium.

Corpus: 19 malicious (synthetic, hand-labelled) + 254 benign (248 real tool definitions, 6 synthetic false-positive regressions).
Benign sources: @modelcontextprotocol/server-filesystem@2026.8.31, @modelcontextprotocol/server-everything@2025.8.18, @modelcontextprotocol/server-memory@2025.8.4, @modelcontextprotocol/server-sequential-thinking@2025.7.1, github/github-mcp-server@c59e8c1 (MIT), microsoft/playwright-mcp@b8b4183 README (Apache-2.0).
Split is frozen: `test` is held out and never tuned against; detectors are tuned only on `dev`.

| split | malicious | benign | TPR (recall) | FPR | precision |
|---|---|---|---|---|---|
| test (held-out) | 12 | 132 | 91.7% | 0.8% | 91.7% |
| dev | 7 | 122 | 100.0% | 0.8% | 87.5% |
| all | 19 | 254 | 94.7% | 0.8% | 90.0% |

## Detection by category (all items)

| category | caught / total |
|---|---|
| hidden-unicode | 4 / 4 |
| embedded-instruction | 8 / 9 |
| exfiltration-hint | 2 / 2 |
| tool-shadowing | 4 / 4 |

## False positives (benign flagged) — every one listed

- github/github-mcp-server@c59e8c1 (MIT) get_notification_details: instruction to the model to invoke or feed another tool
- github/github-mcp-server@c59e8c1 (MIT) list_notifications: instruction to the model to invoke or feed another tool

## False negatives (malicious missed) — every one listed

- embedded-instruction: Adds two numbers.

Caveat: this corpus is small and the malicious set is author-written, so these numbers bound nothing
about novel attacks. They are a regression signal and a floor. The adversarial-evasion suite (Phase 6)
and third-party payloads strengthen it.
