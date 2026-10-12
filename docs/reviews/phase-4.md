# Phase 4 hostile review — rug-pull detection (definition pinning)

Scope: canonical JSON (`canonical.ts`), the lockfile + HMAC key (`lockfile.ts`), the pin checker
(`checker.ts`), the gateway list-time integration (tools, prompts, instructions, and mid-session
`list_changed`), the `approve` / `lock diff` CLI, and the rug-pull / custom fixture servers.

## What Phase 4 adds

`mcphantom approve` records a SHA-256 fingerprint of every server's current tool, prompt, and
instructions definitions (the canonical JSON of the *model-visible* fields) into a lockfile, signed
with an owner-only HMAC key. On every list — including a mid-session `tools/list_changed` — a definition
whose fingerprint no longer matches its pin (**changed** = rug-pull) or that was not approved
(**new**) is hidden in `enforce` mode (default) or kept-and-recorded in `observe` mode. `mcphantom lock
diff` shows live-vs-pinned drift.

Without a lockfile nothing is pinned: everything is `unpinned` and the gateway does not block on
rug-pull grounds — a server poisoned *from the start* is the static scanner's job (Phase 3), while
rug-pull is specifically a change *after* approval.

## HMAC scope — stated precisely (owner note)

The lockfile HMAC is keyed by a 32-byte secret in an owner-only file (`hmac.key`). It protects against
**other OS users** forging or silently editing the lockfile, and against **accidental corruption**. It
does **not** protect against a **same-user** process — including a malicious MCP server, the attacker
already in the threat model — which can read the key and re-sign. An OS credential store
(DPAPI/Keychain/libsecret) would not change this (CurrentUser scope is reachable by any same-user code),
so we use an owner-only key file and say so, rather than implying a guarantee we do not have. The README
and DESIGN.md §1 state this.

## Findings

| # | Severity | Finding | Disposition |
|---|---|---|---|
| R6 | **High (fixed)** | A deeply-nested schema overflowed the recursive canonicaliser with a `RangeError`, and because the per-tool checks ran unguarded inside the list loop, one hostile tool would have failed the **entire** `tools/list`. | **Fixed**: canonicalize has a depth cap (200) that throws a clean, catchable error; each tool/prompt is inspected in a per-item try/catch that hides only that item on any failure (fail-closed). Pinned by `canonicalize` and gateway isolation tests. |
| R1 | Strength | A change confined to a nested property `description` (not the top-level description) is caught — the fingerprint covers the whole input/output schema. | `rugpull.test.ts`. |
| R2–R3 | Strength | Fingerprints are stable across JSON key reordering and equivalent number forms (`1` vs `1.0`), so benign re-serialisation by a server is not a false rug-pull, while any model-visible change is. | Tests. |
| R-mid | Strength | A rug-pull delivered *after* approval via `tools/list_changed` is caught on the re-list, not just at startup. | `rugpull.gateway.test.ts` (flag-file fixture flips a live server). |

## Known limitations carried forward

1. **Same-user tampering** (above): the real boundary is a different OS user / container / sandbox for
   upstream servers, as the threat model has said since Phase 1. The lockfile can also be committed to
   git for code-reviewed changes.
2. **Behavioural rug-pull.** Pinning covers *definitions*. A server that keeps its tool definitions
   identical but changes what the tool *does* at call time is invisible to pinning — that flow is
   caught (if at all) by the runtime taint engine, not here. Documented.
3. **TOFU on first approval.** `approve` trusts whatever is live at that moment; it does not re-scan.
   The scanner (Phase 3) runs independently at list time, so a definition that is both poisoned and
   freshly approved is still hidden by the scanner — but `approve` itself makes no judgement.
4. **`new` tools are blocked in enforce mode.** A server legitimately adding a tool after approval is
   hidden until re-approved. This is the intended secure default (the lockfile is the approved set);
   the remedy is a one-line `mcphantom approve`, shown in the log message.
5. **Resources are not pinned yet.** Only tools, prompts and instructions. Resource definitions change
   less and are routed differently; deferred.

## Test evidence

`npm run check`: lint + typecheck + build clean, **194/194 tests** across 16 files (adds
`rugpull.test.ts`, `rugpull.gateway.test.ts` incl. the mid-session pull and the deep-schema isolation,
and `approve`/`lock diff` in the CLI e2e). The rug-pull and custom fixtures assemble any poisoned text
from fragments so the repo source stays clean.
