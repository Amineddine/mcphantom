# Tier-1 static scanner benchmark

Generated 2026-10-14T03:44:16.832Z · scanner block threshold: medium.

Corpus: 27 malicious (synthetic, hand-labelled) + 260 benign (254 real tool definitions, 6 synthetic false-positive regressions).
Benign sources: @modelcontextprotocol/server-filesystem@2026.8.31, @modelcontextprotocol/server-everything@2025.8.18, @modelcontextprotocol/server-memory@2025.8.4, @modelcontextprotocol/server-sequential-thinking@2025.7.1, github/github-mcp-server@c59e8c1 (MIT), microsoft/playwright-mcp@b8b4183 README (Apache-2.0), author-written dev example (5t): benign tool-routing guidance.
Split is frozen: `test` is held out and never tuned against; detectors are tuned only on `dev`.

| split | malicious | benign | TPR (recall) | FPR | precision |
|---|---|---|---|---|---|
| test (held-out) | 12 | 132 | 100.0% | 0.0% | 100.0% |
| dev | 15 | 128 | 100.0% | 0.0% | 100.0% |
| all | 27 | 260 | 100.0% | 0.0% | 100.0% |

**Tuning round 5t (Phase 6b), before → after, held-out split:** TPR 91.7% (11/12) → 100% (12/12);
FPR 0.8% (1/132) → 0% (0/132). Dev split: TPR 60.0% → 100%, FPR 3.1% → 0% (after adding 8 malicious
full-schema-poisoning and 6 benign tool-routing examples, written before the change). Changes: every
model-visible schema field is scanned (parameter names, `required`, unknown keywords, nested defaults),
hints in structural fields count as medium, and "call this tool" is not read as a redirect to another
tool. **The held-out split had already been observed before this round** (the full-schema-poisoning
miss was seen in PR #5), so the after number is weaker evidence than the first held-out run. One rule
was refined after that held-out run (values of unknown keywords count as structural), prompted by a new
unit test, not by held-out data; the held-out numbers were unchanged by it.

## Detection by category (all items)

| category | caught / total |
|---|---|
| hidden-unicode | 4 / 4 |
| embedded-instruction | 16 / 16 |
| exfiltration-hint | 2 / 2 |
| tool-shadowing | 5 / 5 |

Caveat: this corpus is small and the malicious set is author-written, so these numbers bound nothing
about novel attacks. They are a regression signal and a floor. The adversarial-evasion suite (Phase 6)
and third-party payloads strengthen it.
