# Phase 5 review — CEL policy engine (+ audit of Phases 2–5)

Scope: the CEL wrapper (`src/policy/cel.ts`), custom predicates (`functions.ts`), glob matcher
(`glob.ts`), the policy engine and its merge with the trifecta invariant (`engine.ts`,
`src/taint/engine.ts`), the linter (`lint.ts`), the `policy lint/test/explain` and `suggest` CLI, the
`ask` flow through MCP elicitation, and an end-to-end audit of the Phase 2–5 code written in earlier
sessions.

## What Phase 5 adds

Per-tool rules in the config — `deny` / `ask` / `allow`, each a CEL expression over `arg` and
`context`, with custom predicates `glob()`, `within()`, `containsSecret()` and `from()`. All matching
rules are evaluated; **deny > ask > allow**. A named `declassify` entry is the only way to lift the
trifecta invariant for a call, and it is recorded on the decision. Precedence of the final verdict:
policy deny (or any policy error) → trifecta deny (unless declassified) → ask → allow.

- **`ask`** asks the user through MCP elicitation, naming the tool, rule and argument *names* (not
  values). Only an explicit `accept` + `approve: true` forwards the call; no elicitation support,
  decline, cancel, timeout or a malformed reply all deny.
- **Fail-closed (owner note #1):** a rule referencing an argument absent from the call denies and
  logs; so does any CEL error. An argument guarded by `has(arg.x)` is optional by design and is not
  treated as required (its unguarded use still fails closed via CEL's "no such key" error).
  `mcphantom approve` re-lints the policy against the definitions it just pinned.
- **Cost budget (owner note #2):** AST ≤ 2000 nodes at compile; at evaluation the arguments must be
  ≤ 256 KiB of string data and ≤ 4096 fields, else deny with a clear reason; custom predicates check a
  50 ms deadline. Measured worst cases are in `bench/results/policy-bench.md` (`npm run bench:policy`).
- **Suggestions (owner note #3):** `mcphantom suggest` proposes per-tool classifications from tool
  names and annotations. Annotation-derived ones are labelled **server-claimed**. Only suggestions
  that tighten or match the secure default are applied with `--write`; a looser one (e.g. downgrading
  egress to read) needs `--accept-loose`. No suggestion can ever mark a tool's output trusted.
- `policy lint` checks every `arg.*` reference (guarded or not) against live tool schemas, flags
  rules for tools no server offers, and warns on the bypassable precision-mode predicate `from()`.

## Audit of earlier sessions' work — defects found and fixed

Every item below was proven with a test that **failed** against the pre-audit code
(`test/audit-regressions.test.ts`) and passes after the fix.

| # | Severity | Defect | Fix |
|---|---|---|---|
| AUD-1 | **High** | Prompts were pin-checked under their *namespaced* name (`fx__greet`) while `approve` pins the *original* name, so with a lockfile every prompt read as "new" and was **hidden** in enforce mode (and, had it matched, the fingerprint would have differed anyway). Phase 4's tests only covered tools. | Pin-check with the original prompt definition. |
| AUD-2 | **High** | A policy `ask` returned **allow** ("ask flow not yet wired, allowed with a record") — a fail-open that contradicted DESIGN.md (ask → elicitation, else deny). | `ask` is now its own verdict; elicitation or deny. |
| AUD-7 | **High** | A **malformed** lockfile (e.g. truncated) skipped the refuse check *and* disabled enforcement — corrupting the file silently turned rug-pull protection off. | Malformed is treated like a bad signature: refuse by default; in `warn` mode enforcement stays on with nothing pinned. |
| AUD-6 | Medium | Standalone exfiltration and credential-file hints were rated `medium` and **hid** ordinary tools ("Send a POST to https://api…", Slack webhooks, dotenv loaders). The benign corpus had none of these, so the benchmark missed it. | Standalone hints are `low` (recorded, not hidden); co-occurring hints or hint + instruction still escalate to `high`. Benchmark TPR/FPR unchanged (100% / 0%). |
| AUD-8 | Medium | Layer-2 attribution, which runs *before* the policy size check, had no per-argument or total size bound: a 512 KB argument cost seconds per call (the earlier benchmark run timed out on it). | Attribution capped per leaf (64 KiB), per call (1 MiB total, 512 leaves); exceeding it sets `attributionDegraded` on the decision. Over-budget call: timeout → 9 ms. |
| AUD-4 | Medium | `has(arg.x)` was treated as a required argument, so the idiomatic optional-argument check always denied when the argument was absent. | Test-only selects mark the field guarded; the linter still checks it against the schema. |
| AUD-5 | Low | HMAC key creation renamed over an existing key, so two concurrent `approve` runs could orphan every lockfile signed by the first. | Exclusive `wx` create; on `EEXIST` the existing key is used. |
| AUD-9 | Low | The blocked-call message told the model "this session handled untrusted content and secret data" for *every* block, including plain policy denies — false. | Message now states the actual rule (trifecta / confirmation / policy reason). |
| AUD-3 | — (confirmed OK) | Owner note #1's real scenario — server renames `to`→`recipient` after approval, rug-pull in **observe** mode keeps the tool — was not actually tested before (the earlier "observe" test only set the trifecta to audit). | Added; the policy fails closed as required. |

**Process lesson:** the earlier phases each passed their own tests and CI. All three High defects sat
in paths those tests didn't reach (prompts with a lockfile, `ask`, a corrupt lockfile). Each review
now has to list the paths it *didn't* test, not only the findings it fixed.

## Known limitations carried forward

1. **`ask` without an elicitation-capable client denies.** The dashboard approval queue (DESIGN.md)
   arrives with the dashboard (Phase 8).
2. **`from()` is precision-mode** and bypassable by encoding/paraphrase; lint warns, and Layer 1
   still applies.
3. **The 50 ms deadline is checked inside custom predicates only.** CEL's own evaluation is bounded by
   the AST and argument caps, not by a wall-clock interrupt (synchronous evaluation cannot be pre-empted
   without a worker).
4. **Resources are not pinned yet** — now in the plan before v1 (owner note #4).
5. **`suggest --write` re-serialises the profile**, dropping YAML comments in it.

## Test evidence

`npm run check`: lint + typecheck + build clean, **236/236 tests** across 21 files. `npm run
bench:scanner` (held-out TPR 100% / FPR 0%) and `npm run bench:policy` (all worst cases bounded,
results committed) rerun after the fixes.
