# Tier-1 static scanner benchmark

Generated 2026-10-15T00:31:04.742Z · scanner block threshold: medium.

Corpus: 30 malicious (synthetic, hand-labelled) + 266 benign (248 real tool definitions, 12 author-written dev examples, 6 synthetic false-positive regressions).
Benign sources: @modelcontextprotocol/server-filesystem@2026.8.31, @modelcontextprotocol/server-everything@2025.8.18, @modelcontextprotocol/server-memory@2025.8.4, @modelcontextprotocol/server-sequential-thinking@2025.7.1, github/github-mcp-server@c59e8c1 (MIT), microsoft/playwright-mcp@b8b4183 README (Apache-2.0).
Split is frozen: `test` is held out and never tuned against; detectors are tuned only on `dev`.

| split | malicious | benign | TPR (recall) | FPR | precision |
|---|---|---|---|---|---|
| test (held-out) | 12 | 132 | 100.0% | 0.0% | 100.0% |
| dev | 18 | 134 | 100.0% | 0.0% | 100.0% |
| all | 30 | 266 | 100.0% | 0.0% | 100.0% |

**Tuning round 5t (Phase 6b), before → after, held-out split:** TPR 91.7% (11/12) → 100% (12/12);
FPR 0.8% (1/132) → 0% (0/132). Dev split: TPR 60.0% → 100%, FPR 3.1% → 0% (after adding 8 malicious
full-schema-poisoning and 6 benign tool-routing examples, written before the change). Changes: every
model-visible schema field is scanned (parameter names, `required`, unknown keywords, nested defaults),
hints in structural fields count as medium, and "call this tool" is not read as a redirect to another
tool. **The held-out split had already been observed before this round** (the full-schema-poisoning
miss was seen in PR #5), so the after number is weaker evidence than the first held-out run. One rule
was refined after that held-out run (values of unknown keywords count as structural), prompted by a new
unit test, not by held-out data; the held-out numbers were unchanged by it.

**6b PR 6 (tool-shadowing self-reference), before → after.** The shadowing rule read "this tool" and
"the same tool" as the name of another tool — found on PostHog’s catalog (3 of its 5 hidden tools), not
tuned on it. Dev split, after adding 6 benign self-reference and 3 shadowing examples written before the
change: TPR 100% → 100% (18/18), FPR 4.5% (6/134) → 0%. Held-out (already observed, see above): 100% /
0% before and after. PostHog catalog, reported only: hidden 5 → 2 of 1,121 (`npm run bench:posthog`).

## Detection by category (all items)

| category | caught / total |
|---|---|
| hidden-unicode | 4 / 4 |
| embedded-instruction | 16 / 16 |
| exfiltration-hint | 2 / 2 |
| tool-shadowing | 8 / 8 |

Caveat: this corpus is small and the malicious set is author-written, so these numbers bound nothing
about novel attacks. They are a regression signal and a floor. The adversarial-evasion suite (Phase 6)
and third-party payloads strengthen it.
