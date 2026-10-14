# Entropy detector benchmark (`npm run bench:entropy`)

Node v22.19.0, win32 x64. Deterministic; corpus and seeds in the repository.

| split | benign outputs | flagged (FPR) | random hits | hash-shaped hits | random-secret detection |
|---|---|---|---|---|---|
| dev | 59 | 27 (45.8%) | 158 | 261 | 60/60 (100.0%) |
| test (held out) | 65 | 26 (40.0%) | 154 | 414 | 68/68 (100.0%) |
| all | 124 | 53 (42.7%) | 312 | 675 | 128/128 (100.0%) |

## Detection by kind (all splits)

| kind | classified random | classified hash | missed |
|---|---|---|---|
| base62/20 | 8/8 | 0 | 0 |
| base62/24 | 8/8 | 0 | 0 |
| base62/32 | 8/8 | 0 | 0 |
| base62/40 | 8/8 | 0 | 0 |
| base62/48 | 8/8 | 0 | 0 |
| base62/64 | 8/8 | 0 | 0 |
| base57/44 | 8/8 | 0 | 0 |
| base57/48 | 8/8 | 0 | 0 |
| base64/24 | 8/8 | 0 | 0 |
| base64/44 | 8/8 | 0 | 0 |
| base64/88 | 8/8 | 0 | 0 |
| base64url/22 | 8/8 | 0 | 0 |
| base64url/43 | 8/8 | 0 | 0 |
| base64url/64 | 8/8 | 0 | 0 |
| base36/25 | 8/8 | 0 | 0 |
| base36/32 | 8/8 | 0 | 0 |
| hex/32 | 0/8 | 8 | 0 |
| hex/40 | 0/8 | 8 | 0 |
| hex/64 | 0/8 | 8 | 0 |

Hex values are classified `hash` by design (digests and ids are hex), so a hex-encoded secret is a published miss of this detector.

## Benign outputs with a random hit (all splits)

| group | flagged / outputs |
|---|---|
| real | 11/31 |
| synthetic:aws-s3-head-object | 3/3 |
| synthetic:payments-customer-list | 3/3 |
| synthetic:payments-intent | 3/3 |
| synthetic:analytics-sql-result | 3/3 |
| synthetic:ci-runs-list | 3/3 |
| synthetic:drive-files-list | 3/3 |
| synthetic:app-log-lines | 3/3 |
| synthetic:nanoid-records | 3/3 |
| synthetic:cdn-response-headers | 3/3 |
| synthetic:terraform-state-list | 3/3 |
| synthetic:deployments-list | 3/3 |
| synthetic:video-embed-list | 3/3 |
| synthetic:calendar-events | 3/3 |
| synthetic:base64-thumbnail-json | 3/3 |

CI floor (test split): FPR ≤ 50.0%, detection ≥ 95.0%.
