# Phase 1 hostile review — gateway core

Reviewer stance: a senior security engineer looking for reasons not to trust this code. Scope: everything
in the Phase 1 commit (gateway, upstream connections, config, CLI `run/init/uninstall/doctor`, event store,
redaction, file hardening, CI). Findings are listed with what was done about each.

## What Phase 1 is — and is not

Phase 1 is a **transparent** gateway. It does not yet detect or block anything: tool descriptions and
server `instructions` pass through unscanned, and no taint tracking or policy exists. Anyone running it
today gets namespacing, an audit log, fail-closed handling of unknown methods, denied-by-default sampling,
and hardened local storage — nothing more. The README says this at the top.

## Findings fixed in this phase

| # | Severity | Finding | Fix | Regression test |
|---|---|---|---|---|
| R1 | **High** | `env_inherit` defaulted to `all`: every upstream server received MCPhantom's *entire* environment. SDK-based clients pass only a small allowlist, so inserting MCPhantom would have **widened** what a malicious server can read (e.g. API keys in the client's environment). A security tool must never be a regression. | Default is now `minimal` (the SDK allowlist + configured `env`); `all` is an explicit opt-in documented as risky. | `review-fixes.test.ts` R1 |
| R2 | **High** | Resource URI collisions were resolved "first server in config order wins". A malicious server listing another server's URI (e.g. a `file://` path) could answer reads meant for the other server — resource shadowing. | URIs claimed by more than one server are hidden and reads of them are refused; templates matching several servers were already refused. | R2 |
| R3 | Medium | Unbounded buffering: paginated listings had item and page caps but no byte cap (100 pages × 10 MB), and HTTP upstream bodies had no size limit at all. A hostile server could exhaust the gateway's memory. | Listings capped at 32 MiB serialized; HTTP responses capped at 10 MB (JSON as a whole, SSE per event). **The first version of the SSE limiter was itself bypassable** (oversized event + terminator in one chunk reset the counter before the check) — caught by the new test and fixed. | R3 |
| R4 | Medium | `init` rewrote the client config by temp-file + rename. On Windows the replacement inherits the folder ACL, silently loosening a config the user had restricted (client configs hold credentials). | If the original was owner-only, the replacement is restricted again. | R4 |
| R5 | Low | `uninstall` identified its gateway entry by substring match on the profile name (`"p"` matches almost anything). | Exact match on `--profile <name>` in an entry recognised as the gateway. | R5 |
| R6 | Medium | HTTP upstreams followed redirects to other origins with configured credentials attached. | `redirectPolicy: 'same-origin'`. | — (SDK behaviour; covered by config) |
| B1 | High | `safeCut` (token-safe truncation) trimmed the last token even when the text was *under* the limit, corrupting every short error message in the event log. | Early return for short text. | `redact.test.ts` safeCut |
| B2 | High | The gateway registered prompt/resource/completion handlers even when no upstream offered them; the SDK throws on that, so a gateway in front of a tools-only server **crashed at startup**. | Handlers installed per advertised capability; others hit the fail-closed fallback. | `gateway.test.ts` pagination tests (tools-only server) |
| B3 | Medium | A store that failed to open (newer schema) leaked its DB handle, locking the file on Windows for every other process. | Handle closed on any open/migrate failure. | `store.test.ts` newer schema |
| B4 | Medium | System binaries (`whoami`, `icacls`) were resolved through `PATH`: Git for Windows' GNU `whoami` broke ACL hardening, and PATH resolution is a hijack vector. | Absolute `%SystemRoot%\System32` paths. | `store.test.ts` permission tests (Windows) |
| B5 | Low | Upstream JSON-RPC errors were re-wrapped so their message differed from a direct connection. | Upstream wire message forwarded verbatim. | conformance: JSON-RPC errors |
| B6 | Low | Invalid server ids produced "Invalid key in record". | The underlying rule is surfaced. | `config.test.ts` |

## Known weaknesses accepted for now (tracked, not hidden)

1. **No protection yet** (by design of the phase plan). Poisoned descriptions and `instructions` reach the
   model exactly as without MCPhantom. Phase 2 adds the trifecta invariant; Phase 3 list-time scanning.
2. **Linux and macOS are unverified locally.** Development happened on Windows 11; the POSIX permission
   code (`0700`/`0600`, owner uid check) has unit coverage only through the code paths that run on
   Windows. CI covers Ubuntu and macOS but **has not run yet** because there is no GitHub remote — pushing
   requires the owner's confirmation. Until CI is green on all three OSes, POSIX support is a claim, not a
   result.
3. **The event log fails open.** A write failure is reported once on stderr and requests continue. The log
   is an audit trail, not a control; making a full disk take down the agent is the wrong trade. Policy
   decisions (Phase 2+) will not depend on the store.
4. **Redaction is pattern-based.** It catches the listed credential formats, configured secrets (and their
   base64/URL encodings), and values under sensitive keys. A random 40-character token with no prefix and
   no keyword is **not** redacted. An entropy detector arrives with the secret detectors in Phase 6.
5. **Same-user tampering.** Owner-only permissions keep other OS users out; they do nothing against an
   upstream server running as the same user, which can rewrite the profile or read the DB. DESIGN.md §1
   documents the mitigations planned for the lockfile (Phase 4).
6. **No upstream restart.** A crashed server stays down for the session (the client is told via
   `tools/list_changed`). Restart with backoff is deferred; restarting a server that crashed while under
   attack is not obviously the safe default.
7. **Resource routing fallback.** A URI that is neither listed nor matches a template is routed to the
   only resource-capable server, if exactly one exists. Transparent, but permissive; Phase 3/5 revisit it.
8. **Latency.** ~37 ms extra at 1 MB per call, dominated by double SDK parsing/validation across the extra
   hop (measured: unchanged with payload logging off). Low single-digit ms for small payloads, within this
   laptop's noise. See `bench/results/phase1-latency.md` for all three runs.
9. **`title` spoofing.** A server can give its tool a `title` that names another server's tool. Names are
   unforgeable (namespaced); titles are not. Scanner phase.

## Test evidence

`npm run check` on Windows 11 / Node 22.19: lint clean, typecheck clean, build OK, **112/112 tests**
across 8 files (conformance, gateway behaviour, redaction incl. ReDoS timing, store, permissions, config,
init/uninstall, review regressions). The CLI e2e suite also passes against the built `dist/` (4/4), and a
packed tarball installs into a fresh prefix and runs (`--version`, `doctor`).
