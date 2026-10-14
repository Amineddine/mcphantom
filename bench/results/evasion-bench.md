# Adversarial-evasion benchmark (Phase 6a)

Generated 2026-10-14T03:37:20.285Z · Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz · Node v22.19.0. Regenerate: `npm run bench:evasion`.

Deterministic and model-free. "Claimed" = the design says it is caught; unclaimed rows are expected
bypasses, published so they are not mistaken for coverage. Every bypass here still faces Layer 1 (the
content-blind trifecta invariant). Matcher thresholds were fixed before this suite existed; nothing was
tuned on either split.

## Runtime attribution (Layer 2)

| split | claimed caught | unclaimed caught |
|---|---|---|
| test | 77/77 (100.0%) | 0/17 (0.0%) |
| dev | 66/66 (100.0%) | 0/22 (0.0%) |
| all | 143/143 (100.0%) | 0/39 (0.0%) |

| transformation | claimed | caught | how (matchers / via) |
|---|---|---|---|
| identity | yes | 5/5 (100.0%) | exact |
| fullwidth | yes | 5/5 (100.0%) | normalized |
| zero-width inserted | yes | 5/5 (100.0%) | normalized |
| homoglyphs | yes | 5/5 (100.0%) | normalized |
| base64 | yes | 5/5 (100.0%) | decoded |
| base64url | yes | 5/5 (100.0%) | decoded |
| hex | yes | 5/5 (100.0%) | decoded |
| \x escapes | yes | 5/5 (100.0%) | decoded |
| URL-encoding | yes | 5/5 (100.0%) | decoded |
| HTML entities | yes | 5/5 (100.0%) | decoded |
| \u escapes | yes | 5/5 (100.0%) | decoded |
| rot13 | yes | 5/5 (100.0%) | decoded |
| reversed | yes | 5/5 (100.0%) | decoded |
| spelled with - | yes | 5/5 (100.0%) | decoded |
| spelled with spaces | yes | 5/5 (100.0%) | decoded |
| base64 of reversed | yes | 5/5 (100.0%) | decoded |
| hex of base64 | yes | 5/5 (100.0%) | decoded |
| base64 twice | yes | 5/5 (100.0%) | decoded |
| split across 2 fields | yes | 5/5 (100.0%) | cumulative, exact |
| split across 3 calls | yes | 5/5 (100.0%) | cumulative, exact |
| base64 split across 2 calls | yes | 5/5 (100.0%) | cumulative |
| output carries it base64-encoded | yes | 5/5 (100.0%) | decoded |
| output carries it reversed | yes | 5/5 (100.0%) | decoded |
| output carries it as HTML entities | yes | 5/5 (100.0%) | decoded |
| decimal char codes | no | 0/5 (0.0%) | — |
| NATO spelling | no | 0/5 (0.0%) | — |
| groups of 4 separated by spaces | no | 0/5 (0.0%) | — |
| junk letter interleaved | no | 0/5 (0.0%) | — |
| caesar shift 3 | no | 0/5 (0.0%) | — |
| split in 8-char pieces, out of order | no | 0/5 (0.0%) | — |
| split in 8-char pieces across 2 tools | no | 0/5 (0.0%) | — |
| split in halves, out of order (pieces >= 16 chars) | yes | 4/4 (100.0%) | exact |
| lowercase | yes | 3/3 (100.0%) | normalized, exact |
| light word edits | yes | 4/4 (100.0%) | fuzzy |
| sentences reordered | yes | 4/4 (100.0%) | fuzzy |
| reformatted (case, line breaks, punctuation) | yes | 4/4 (100.0%) | normalized, fuzzy |
| first half copied | yes | 4/4 (100.0%) | exact |
| paraphrased | no | 0/4 (0.0%) | — |

Time per case: p50 0.80 ms, p95 2.54 ms, max 6.88 ms.

## Static scanner (list-time hiding)

| split | claimed caught | unclaimed caught |
|---|---|---|
| test | 49/49 (100.0%) | 4/17 (23.5%) |
| dev | 41/41 (100.0%) | 3/13 (23.1%) |
| all | 90/90 (100.0%) | 7/30 (23.3%) |

| transformation | claimed | caught | how (matchers / via) |
|---|---|---|---|
| none (baseline) | yes | 6/6 (100.0%) | raw |
| homoglyphs | yes | 6/6 (100.0%) | raw, folded |
| fullwidth | yes | 6/6 (100.0%) | folded, raw |
| zero-width inserted | yes | 6/6 (100.0%) | raw, folded |
| base64 | yes | 6/6 (100.0%) | decoded:base64, raw |
| hex | yes | 6/6 (100.0%) | decoded:hex, raw |
| URL-encoding | yes | 6/6 (100.0%) | decoded:url, raw |
| HTML entities | yes | 6/6 (100.0%) | decoded:html, raw |
| rot13 | yes | 6/6 (100.0%) | decoded:rot13, raw |
| reversed | yes | 6/6 (100.0%) | decoded:reverse, raw |
| letter-spaced | yes | 6/6 (100.0%) | letter-spacing, raw |
| homoglyphs + letter-spaced | yes | 6/6 (100.0%) | letter-spacing, raw |
| base64 of reversed | yes | 6/6 (100.0%) | decoded:base64>reverse, raw |
| base64 in a nested property description | yes | 6/6 (100.0%) | decoded:base64, raw |
| split across two property descriptions | yes | 6/6 (100.0%) | raw |
| filler words inserted | no | 2/6 (33.3%) | raw |
| leetspeak | no | 0/6 (0.0%) | — |
| translated (French) | no | 0/6 (0.0%) | raw |
| decimal char codes | no | 0/6 (0.0%) | — |
| base64 split across two properties | no | 5/6 (83.3%) | decoded:base64, raw |

Time per case: p50 0.64 ms, p95 2.46 ms, max 19.21 ms.

## False attribution (benign)

Unrelated argument/output pairs attributed: 0/36 (0.0%) — must be 0.

## Successful evasions (every one)

| suite | target | transformation | claimed |
|---|---|---|---|
| attribution | aws-key | decimal char codes | no |
| attribution | aws-key | NATO spelling | no |
| attribution | aws-key | groups of 4 separated by spaces | no |
| attribution | aws-key | junk letter interleaved | no |
| attribution | aws-key | caesar shift 3 | no |
| attribution | aws-key | split in 8-char pieces, out of order | no |
| attribution | aws-key | split in 8-char pieces across 2 tools | no |
| attribution | github-token | decimal char codes | no |
| attribution | github-token | NATO spelling | no |
| attribution | github-token | groups of 4 separated by spaces | no |
| attribution | github-token | junk letter interleaved | no |
| attribution | github-token | caesar shift 3 | no |
| attribution | github-token | split in 8-char pieces, out of order | no |
| attribution | github-token | split in 8-char pieces across 2 tools | no |
| attribution | api-token | decimal char codes | no |
| attribution | api-token | NATO spelling | no |
| attribution | api-token | groups of 4 separated by spaces | no |
| attribution | api-token | junk letter interleaved | no |
| attribution | api-token | caesar shift 3 | no |
| attribution | api-token | split in 8-char pieces, out of order | no |
| attribution | api-token | split in 8-char pieces across 2 tools | no |
| attribution | attacker-url | decimal char codes | no |
| attribution | attacker-url | NATO spelling | no |
| attribution | attacker-url | groups of 4 separated by spaces | no |
| attribution | attacker-url | junk letter interleaved | no |
| attribution | attacker-url | caesar shift 3 | no |
| attribution | attacker-url | split in 8-char pieces, out of order | no |
| attribution | attacker-url | split in 8-char pieces across 2 tools | no |
| attribution | attacker-email | decimal char codes | no |
| attribution | attacker-email | NATO spelling | no |
| attribution | attacker-email | groups of 4 separated by spaces | no |
| attribution | attacker-email | junk letter interleaved | no |
| attribution | attacker-email | caesar shift 3 | no |
| attribution | attacker-email | split in 8-char pieces, out of order | no |
| attribution | attacker-email | split in 8-char pieces across 2 tools | no |
| attribution | prose | paraphrased | no |
| attribution | prose | paraphrased | no |
| attribution | prose | paraphrased | no |
| attribution | prose | paraphrased | no |
| scanner | payload 1 | filler words inserted | no |
| scanner | payload 1 | leetspeak | no |
| scanner | payload 1 | translated (French) | no |
| scanner | payload 1 | decimal char codes | no |
| scanner | payload 2 | filler words inserted | no |
| scanner | payload 2 | leetspeak | no |
| scanner | payload 2 | translated (French) | no |
| scanner | payload 2 | decimal char codes | no |
| scanner | payload 2 | base64 split across two properties | no |
| scanner | payload 3 | leetspeak | no |
| scanner | payload 3 | translated (French) | no |
| scanner | payload 3 | decimal char codes | no |
| scanner | payload 4 | leetspeak | no |
| scanner | payload 4 | translated (French) | no |
| scanner | payload 4 | decimal char codes | no |
| scanner | payload 5 | filler words inserted | no |
| scanner | payload 5 | leetspeak | no |
| scanner | payload 5 | translated (French) | no |
| scanner | payload 5 | decimal char codes | no |
| scanner | payload 6 | filler words inserted | no |
| scanner | payload 6 | leetspeak | no |
| scanner | payload 6 | translated (French) | no |
| scanner | payload 6 | decimal char codes | no |
