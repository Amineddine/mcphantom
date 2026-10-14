# Entropy detector benchmark (`npm run bench:entropy`)

Node v22.19.0, win32 x64. Deterministic; corpus and seeds in the repository.
FPR = benign outputs with at least one `random` hit (only `random` hits can escalate). Detection = generated
secrets classified `random`, over every generated secret, including the kinds missed by design.

| split | benign outputs flagged (FPR) | random hits | id-shaped hits | detection |
|---|---|---|---|---|
| **before** dev | 27/59 (45.8%) | 158 | 261 | 72/85 (84.7%) |
| **before** test (held out) | 26/65 (40.0%) | 154 | 414 | 80/91 (87.9%) |
| after dev | 8/59 (13.6%) | 40 | 377 | 64/85 (75.3%) |
| after test (held out) | 6/65 (9.2%) | 40 | 527 | 71/91 (78.0%) |
| after all | 14/124 (11.3%) | 80 | 904 | 135/176 (76.7%) |

"Before" is the first detector (PR #2 as opened), measured by this same benchmark. Tuning used the dev split
only; the test split was run once, after the parameters were frozen.

**Known defect, seen on the held-out split and deliberately not fixed in this round:** the local part of an
e-mail address (`170738883+…` in a GitHub noreply address) is tokenised as a possible secret; it accounts
for 4 of the 6 flagged held-out outputs. It was also visible on the dev split and was missed during tuning.
Fixing it now would tune against the held-out data, so it is the first item of the next tuning round,
which needs a fresh held-out split.

## Detection by kind (all splits, after)

| kind | classified random | classified id | missed |
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
| base64url/43 | 7/8 | 1 | 0 |
| base64url/64 | 8/8 | 0 | 0 |
| base36/25 | 8/8 | 0 | 0 |
| base36/32 | 8/8 | 0 | 0 |
| hex/32 | 0/8 | 8 | 0 |
| hex/40 | 0/8 | 8 | 0 |
| hex/64 | 0/8 | 8 | 0 |
| unknown-vendor prefix zq_/40 | 0/8 | 8 | 0 |
| under an "id" field/40 | 0/8 | 8 | 0 |
| under "secret_id"/40 | 8/8 | 0 | 0 |

## Remaining false positives by token shape (all splits, after)

| shape | random hits | outputs |
|---|---|---|
| lowercase+digits (base36) 25-32 | 50 | 6 |
| base64 (+ / =) 20-24 | 26 | 4 |
| base64url (- _) 33-48 | 3 | 3 |
| base64 (+ / =) 33-48 | 1 | 1 |

## Remaining false positives by output type (all splits, after)

| output type | flagged / outputs |
|---|---|
| real:git | 2/5 |
| real:package | 1/3 |
| real:gh | 2/6 |
| synthetic:analytics-sql-result | 3/3 |
| synthetic:app-log-lines | 3/3 |
| synthetic:cdn-response-headers | 3/3 |

CI floor (test split): FPR ≤ 15.0%, detection ≥ 70.0%.
