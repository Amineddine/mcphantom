# MCPhantom — Design

Status: **approved with changes (2026-10-12)**. This document is the source of truth for scope and
sequencing; deviations are recorded in the "Change log" at the end.

MCPhantom is a security gateway that sits between an LLM agent's MCP client and the MCP servers it
uses. It scans and pins tool definitions, tracks the provenance of data flowing through tool calls,
and enforces a declarative per-tool policy — including across the LLM boundary, where data is
paraphrased rather than copied.

---

## 1. Architecture

```
 ┌─────────────┐        stdio          ┌──────────────────────────── MCPhantom gateway ─────────────────────────┐
 │ MCP client  │◄─────────────────────►│ Downstream face (MCP Server, official SDK)                               │
 │ Claude Code │                       │     │                                                                    │
 │ Desktop,    │                       │ ┌───▼──────────── Interception pipeline ───────────────────────────────┐ │
 │ Cursor, ... │                       │ │ 1 Definition gate  pin check (rug-pull) + scanner verdict            │ │
 └─────────────┘                       │ │                    → filters tools/list BEFORE the LLM sees it       │ │
                                       │ │ 2 Call gate        policy: context labels + arg provenance           │ │
                                       │ │                    → allow / ask / deny                               │ │
                                       │ │ 3 Output gate      labels, secret + injection scan, provenance index │ │
                                       │ └───┬──────────────────────────────────────────────────────────────────┘ │
                                       │     │     Session store (labels, bounded provenance index)              │
                                       │ Upstream face (one MCP Client per server)   Event log (SQLite, redacted) │
                                       └─────┼────────────────┼─────────────────────────────┼─────────────────────┘
                                             ▼  stdio / HTTP  ▼                             ▼ SSE (loopback)
                                        server A          server B                   Dashboard
```

### Deployment: gateway mode only (v1)

The client config contains a single `mcphantom` entry. MCPhantom spawns/connects every upstream
server listed in its own config and exposes their tools as `<serverId>__<tool>`. Gateway mode is the
only mode in which one process observes every tool call of a session, which cross-server taint
tracking requires. **Wrap mode (per-server shims + daemon) is deferred to a later release.**

- Downstream transport (client → MCPhantom): stdio. (Streamable HTTP downstream is a later addition.)
- Upstream transports (MCPhantom → servers): stdio and Streamable HTTP.
- `mcphantom init` discovers client configs (Claude Code project `.mcp.json`, Claude Desktop,
  Cursor), moves their server entries into the MCPhantom config, replaces them with one `mcphantom`
  entry, shows a diff, writes a backup, and offers bulk classification suggestions (see §3.4).
  `mcphantom uninstall` restores the backup. Paths are resolved per-OS; Windows is first-class.

### Protocol handling rules

- Every method the gateway serves has an explicit handler; it never forwards raw JSON-RPC blindly.
  Handled: `initialize`, `ping`, `tools/list|call`, `resources/list|read|templates/list|subscribe|unsubscribe`,
  `prompts/list|get`, `completion/complete`, `logging/setLevel`; notifications for list changes,
  progress, cancellation, logging, resource updates. **Unknown methods are rejected** (MethodNotFound).
- `tools/list` (and the other list methods) are fully paginated upstream by the gateway — every page
  is fetched and inspected — and returned downstream as one result, bounded by a hard cap.
- Server→client requests: `roots/list` and `elicitation/create` are relayed; **`sampling/createMessage`
  is denied by default** (it lets a server inject text straight into the model) and can be enabled
  per server.
- Experimental `tasks` are not advertised in v1.
- **Fail closed**: an internal error in any gate denies the request and logs the cause.
- Server-provided annotations (`readOnlyHint`, `destructiveHint`, `openWorldHint`, …) are
  attacker-controlled. They may *tighten* a classification or seed `init` suggestions; they never
  loosen policy.
- Poisoning is stopped at list time: a flagged or unpinned tool is removed from `tools/list`, since
  a description injects into the model the moment it is listed. The server's `instructions` field in
  the `initialize` result is scanned and pinned the same way.

### MCPhantom's own storage is attack surface

| Asset | Protection |
|---|---|
| Event log (SQLite DB + WAL/SHM) | Payloads pass through the secret redactor **before** being written. `log_payloads: redacted (default) \| none \| full`. Retention by age and size (`retention.days`, `retention.max_mb`), pruned at startup and hourly. |
| DB, lockfile, policy, config | POSIX: directory `0700`, files `0600`, created with a restrictive umask. Windows: inheritance removed and a single full-control ACE for the current user's SID (`icacls /inheritance:r /grant:r *<SID>:(OI)(CI)F` on the directory, `(F)` on files) — the 0600 equivalent. Checked at startup; MCPhantom refuses to start (or warns, configurable) if the files are group/world accessible. Covered by CI on Windows, macOS and Linux. |
| Dashboard | Loopback bind, random per-run token, Host-header allowlist (anti-DNS-rebinding), Origin/CSRF checks, strict CSP, tool output rendered as text only. |

**Same-user tampering (threat model entry).** Upstream stdio servers run as the same OS user as
MCPhantom. File permissions do not stop a same-user process from rewriting the lockfile or policy.
Mitigations, in decreasing strength — none is a real boundary:

1. Lockfile and policy are read once at startup and hashed; changes made while MCPhantom runs are
   ignored until the user reloads through the CLI, which shows a diff. A tampering server must
   therefore win a race before the next restart, and the change shows up in `mcphantom lock diff`.
2. Lockfile entries carry an HMAC keyed by a secret held in the OS credential store (DPAPI on Windows,
   Keychain on macOS, libsecret on Linux). This defeats naive file edits; it does **not** stop a
   same-user process that calls the same APIs (DPAPI CurrentUser is reachable by any same-user code).
3. Project lockfiles can be committed to git so that changes are code-reviewed.

The real boundary is running upstream servers under a different OS user, in a container, or in a
sandbox. The docs say so plainly.

---

## 2. Taint tracking across the LLM boundary

MCPhantom sees tool outputs entering the model and tool arguments leaving it; it never sees the
model's context, its reasoning, or the user's prompt. Nothing in the middle can prove that data did
**not** flow through the model. Two layers with different jobs follow.

### Layer 1 — context labels (sound)

Labels form two lattices: integrity `trusted ⊑ untrusted`, confidentiality
`public ⊑ internal ⊑ secret`. Each output is labeled by policy (per server/tool, optionally per
argument). The session **context label** is the monotone join of everything ingested. Once untrusted
content is in the context, every later call is presumed attacker-steerable, regardless of paraphrase.

**Trifecta invariant (default on):** an `egress` call while the context is both `untrusted` and
`secret` is denied unless a named `declassify` entry allows it. Paraphrase cannot bypass this layer
because it does not inspect content. Its cost is over-tainting, which the policy language and Layer 2
make tolerable without giving up soundness.

### Layer 2 — argument provenance (precise)

For each string leaf of a call's arguments: *which earlier outputs did this come from, by which
matcher, with what confidence?*

| Matcher | Catches |
|---|---|
| Exact substring | verbatim copy |
| Normalized | case, whitespace, NFKC, zero-width, homoglyphs |
| Decoded | base64, hex, URL, HTML entities, `\u` escapes, rot13, reversal, separator spelling (args decoded recursively, bounded depth) |
| Fuzzy | light edits/reordering (winnowing k-gram fingerprints) |
| Cumulative | exfiltration split across many calls (per-sink reassembly) |
| Semantic | paraphrase (local embeddings; optional, kept only if measured gain justifies cost) |

**Core insight.** The security-critical parts of an exfiltration — the *destination* (attacker URL,
address) and the *secret* (key, token) — are high-entropy identifiers that must cross the LLM
boundary *exactly* or the attack fails. They are attributable by matchers that hold up under
adversarial pressure (exact/normalized/decoded/cumulative) even when the surrounding prose is
paraphrased. Paraphrase only defeats attribution for low-entropy payloads, which Layer 1 still covers.

**Honesty rule.** Layer-2 evidence may add restrictions, explain a decision, or satisfy an
author-written allow rule (e.g. "recipient not from untrusted"). The absence of a match is never
treated as proof of absence of flow; any policy relying on that gets a "precision-mode, bypassable"
lint warning.

Every server also receives its arguments, so every `tools/call` is egress to that server's operator:
per-server `may_receive` bounds the confidentiality of what may be sent to it.

### Bounded memory and eviction

The provenance index and the cumulative-reassembly buffers are bounded per session and globally:

- **Tier A — full text** (needed for fuzzy/semantic matching): LRU by ingestion time, byte budget
  (default 32 MiB per session, 256 MiB global).
- **Tier B — identifier fingerprints**: hashes of high-entropy tokens extracted from every output
  (secrets, URLs, e-mail addresses, hostnames, long tokens). Small (tens of bytes each); kept far longer
  than Tier A under a separate budget (default 4 MiB per session). When Tier A text is evicted,
  exact/normalized/decoded attribution of *identifiers* still works through Tier B.
- **Cumulative buffers**: per (session, sink) byte cap and time window.

Eviction **never silently weakens protection**:

1. Layer-1 labels are a running join and do not depend on the index; evicted data still taints.
2. Every eviction emits an `eviction` event (what tier, how many bytes, label of the evicted output).
3. A decision made after an eviction that dropped data with a non-public or untrusted label carries
   an `attribution_degraded` flag, visible in the trace and the dashboard.
4. The benchmark reports memory (RSS and index bytes) and **attribution loss caused by eviction**:
   the same scenarios replayed at several budgets, counting decisions whose evidence changed.

### Secrets

Identified by (a) policy-declared sources (e.g. `read_file` of `~/.ssh/**`, `**/.env*`),
(b) detectors run on every output (gitleaks-style rules + entropy), (c) canary tokens used by the
demo and benchmark. The same detector feeds log redaction.

### Ask decisions

Routed to MCP `elicitation` if the client supports it, else a dashboard approval queue with a
timeout, else deny.

---

## 3. Policy language

### 3.1 Shape

YAML documents with expressions in conditions:

```yaml
version: 1
defaults:
  unknown_tool:    { effect: egress, output: { integrity: untrusted } }   # secure default
  on_violation:    deny            # deny | ask | log
  unknown_methods: deny

servers:
  web:
    trust: { integrity: untrusted, may_receive: [public] }
    tools:
      fetch: { effect: read }
  fs:
    trust: { integrity: trusted, may_receive: [public, internal, secret] }
    tools:
      read_file:
        effect: read
        output:
          confidentiality:
            - secret:   'glob(arg.path, ["~/.ssh/**", "**/.env*", "**/*credentials*"])'
            - internal: 'true'
      write_file:
        effect: write
        allow: [ 'within(arg.path, "./workspace")' ]
  mail:
    trust: { integrity: trusted, may_receive: [public, internal] }
    tools:
      send_email:
        effect: egress
        rules:
          - deny:  'from(arg.to, "untrusted")'
          - deny:  'containsSecret(arg)'
          - ask:   'context.integrity == "untrusted"'
          - allow: 'arg.to in ["me@corp.example"]'

declassify:
  - id: weekly-report
    tool: mail__send_email
    when: 'arg.to == "me@corp.example"'
    reason: "User's own inbox; accepted risk"
```

Effects: `read | write | egress | exec`. All matching rules are evaluated; **deny > ask > allow**. An
`allow` overrides a default but never an explicit `deny`. Global invariants (trifecta) are lifted only
by a named `declassify` entry, which is recorded on every decision it affects. Every decision records
the rule id that produced it.

### 3.2 Expression language: CEL vs a hand-written parser — **recommendation: CEL via `@bufbuild/cel`**

Evaluated `@bufbuild/cel` 0.6.1 (Buf, Apache-2.0), `@marcbachmann/cel-js` 8.0.0, `cel-js` 0.8.2, and a
hand-written Pratt parser.

| Criterion | `@bufbuild/cel` | hand-written |
|---|---|---|
| Semantics | Published CEL spec; depends on `@bufbuild/cel-spec` (the spec's protobuf definitions, including the conformance service). Conformance level not yet verified by us — our contract tests pin the behaviours we rely on | Ours; we would have to specify and test everything |
| Termination | Guaranteed by language design (no loops/recursion; macros bounded by input size) | Guaranteed only if we get it right |
| Regex | RE2 semantics via `@bufbuild/re2` — linear time, no ReDoS | We would need to pull in RE2 anyway |
| Familiarity to reviewers | High: Kubernetes admission policies, Envoy RBAC, Google IAM conditions | None |
| Custom predicates (`from`, `containsSecret`, `glob`, `within`) | Registered functions (`celFunc`) | Native |
| Type-checking against tool schemas | Its checker is **not** part of the public export map, so we validate on the parsed AST ourselves (walk `arg.*` selections and check them against each tool's `inputSchema`) | Native |
| Error messages | Generic; we wrap them with file/rule location | Tailored |
| Cost | ~11 MB installed (includes cel-spec protobuf descriptors), 0.x API | ~1–2k LOC + a fuzzing harness to maintain |

`@marcbachmann/cel-js` is small (~270 KB) but compiles `matches()` to native `RegExp`, which
reintroduces ReDoS; `cel-js` (ChromeGG) is unmaintained since 2025-07.

**Decision:** CEL via `@bufbuild/cel`, version pinned exactly, wrapped behind our own `PolicyExpr`
interface so the evaluator can be swapped. Mitigations for its weaknesses: our own AST-level schema
lint; expression length and AST-node limits at load time; an evaluation-time cost guard; a contract
test suite that pins the CEL behaviours we depend on, so an upgrade that changes semantics fails CI.

### 3.3 Tooling

`mcphantom policy lint` (schema errors, unknown args, unreachable rules, precision-mode warnings),
`mcphantom policy test` (YAML fixtures), `mcphantom policy explain <event-id>`.

### 3.4 Secure defaults and `init` suggestions

Unknown tools are `egress` with `untrusted` output. `mcphantom init` connects to each server, reads
its tools, and proposes a classification table derived from annotations and names
(`readOnlyHint: true` → suggest `read`; `openWorldHint` → suggest untrusted output; names like
`fetch|browse|search|read_email` → untrusted output). The user can accept them in bulk, edit them, or
reject them. Accepted suggestions are written to the policy as explicit entries with a
`# suggested from annotations` comment; nothing is applied implicitly.

---

## 4. Storage engine — **recommendation: `better-sqlite3`**

`node:sqlite` is available unflagged from Node 22.13 but is still marked experimental (stability 1.x) and
prints an `ExperimentalWarning`, which would end up on stderr of every MCP session.
`better-sqlite3` 13 is mature, synchronous (simple, fast, safe ordering of writes), supports WAL, and
ships prebuilt binaries for Windows/macOS/Linux on x64 and arm64 for current Node LTS versions, so
`npm i -g mcphantom` does not need a compiler on supported platforms. Costs: a native dependency
(supply chain and prebuild availability). Mitigation: all storage goes through a `Store` interface;
moving to `node:sqlite` once it is stable is a contained change. CI installs on all three OSes.

---

## 5. Phase plan

Every phase ends with green CI, a commit, and a written hostile review with its fixes applied.

| # | Milestone | Proof |
|---|---|---|
| 1 | **Gateway core.** stdio downstream; stdio + Streamable HTTP upstream; namespacing; full method coverage + fail-closed; sampling denied by default; config loading; event log through `Store` with redaction, retention and file hardening (POSIX modes + Windows ACLs); CLI `run`, `init` (Claude Code `.mcp.json`, Claude Desktop, Cursor; diff + backup) and `uninstall`; CI on Windows/macOS/Linux × Node 22/24 | Conformance tests (direct vs. proxied results equal), permission tests per OS, redaction tests, baseline latency measured |
| 2 | **Vertical slice.** Labels, context label, trifecta invariant, exact + normalized matchers, minimal built-in classification config; attack servers for the demo (poisoned web page via fetch, filesystem with canary secrets, attacker sink); deterministic scripted-agent end-to-end test; **basic side-by-side demo through Claude Code** (unprotected vs. MCPhantom), with the exfiltration oracle being the sink's own log | The demo runs from one command; the deterministic e2e test runs in CI |
| 3 | **Static scanner** + list-time filtering; attack servers for poisoning (hidden instructions, Unicode tags / zero-width / bidi, schema-level, `instructions`, shadowing, excessive permissions); benign corpus of real public server definitions; tier-1 static benchmark | TPR/FPR on a frozen held-out split |
| 4 | **Rug-pull defense.** RFC 8785 canonical JSON + SHA-256 pins in `mcphantom.lock` (HMAC via OS credential store), `approve`/`lock diff`, enforcement on `list_changed` and re-list, per-session inconsistency detection; rug-pull attack servers | Delayed / silent / paginated / per-session rug-pulls caught; tamper tests |
| 5 | **Policy engine (CEL).** Loader, AST schema lint, evaluator, deny>ask>allow, declassify, `lint`/`test`/`explain`; `init` bulk classification suggestions | Contract tests on CEL semantics, property + fuzz tests |
| 6 | **Taint deepening.** Decoded/fuzzy/cumulative matchers, secret detectors, Tier A/B bounded index with eviction events and `attribution_degraded`, elicitation/ask flow; exfiltration attack servers | Adversarial evasion suite, with the evasions that succeed published |
| 7 | **Semantic layer + tier-1 runtime benchmark** (`mcp-attack-bench`), adapter spec, latency + memory + eviction-loss benchmarks | Numbers and methodology published |
| 8 | **Dashboard** ("Blacklight") | Playwright e2e + dashboard security tests |
| 9 | **Showcase + Tier-2 live runs.** The headline demo uses **real Claude Code as the MCP client against a real poisoned page**, with a **replay mode** (recorded real transcript, model + date shown) for anyone without Claude Code. The demo must run **from the installed package — `npx mcphantom demo`** — not only a dev checkout. Tier-2 bulk runs: Ollama default; Anthropic API behind a flag with the USD-50 cap. The deterministic `npm run demo` is kept as the CI regression test. | Live attack-success rates with confidence intervals; `npx mcphantom demo` works from a clean global install; replay mode needs no network or model |
| 10 | **Docs + release**: README, architecture diagram, threat model, known bypasses, write-up, demo GIF; GitHub + npm (each push/publish confirmed with the owner first) | Every claim linked to a reproducible command |

### Repository security (enable when GitHub Pro is active)

The repo is a free private repo today, so GitHub refuses secret scanning, push protection and branch
protection. The owner is applying for GitHub Pro via the Student Developer Pack; when it is active,
enable, as originally planned: **secret scanning**, **push protection**, and **branch protection on
`main` requiring the CI and gitleaks checks to pass before merge** (the ruleset JSON is ready in the
Phase-1 notes). Until then the gitleaks CI job is the stand-in and `main` is unprotected.

---

## 6. Benchmark — `mcp-attack-bench`

- **Scored unit:** anything that speaks MCP in the middle. Runtime defenses are scored black-box as an
  MCP proxy between agent and servers; static scanners via a JSON in/out adapter.
- **Scenarios** are declarative: servers, seeded canary secrets, benign user task, attacker payload
  and injection point, and two oracles independent of the defense — *attack success* (canary or
  attacker action observed in the sink server's own log) and *utility* (benign task completed).
- **Tier 1 — deterministic, no model, runs in CI.** Static: labeled tool-definition corpora → TPR,
  FPR, precision per category. Runtime: recorded tool-call traces (with pre-generated paraphrase and
  encoding variants) replayed through the defense → block rate, false-block rate.
- **Tier 2 — live agents.** Default backend: a local open-weights model through **Ollama**. Optional
  backend: Anthropic API behind `--backend anthropic`, with a **hard cap of USD 50 total** tracked in a
  local ledger; before every batch the harness prints the estimated cost (tokens × published price)
  and requires explicit confirmation; batches that would exceed the cap are refused. Metrics: attack
  success rate, utility under attack, benign utility, with Wilson 95% intervals, model ids, dates, seeds.
- **Live demo** uses Claude Code (the owner's subscription) as the MCP client — no API spend.
- **Latency:** proxy overhead in isolation (null echo server) and against real servers; p50/p95/p99
  after warmup; output sizes 1 KB–1 MB; with/without semantic layer; hardware and Node version recorded.
- **Memory:** RSS and index bytes per scenario; attribution loss at reduced memory budgets (§2).
- **Tracked regression — 1 MB results:** Phase 1 measured ~37 ms extra per call at 1 MB (three runs,
  one machine; `bench/results/phase1-latency.md`). The Phase 7 benchmark must report it with repeated runs
  (≥ 10 independent process launches per configuration), bootstrap 95% confidence intervals on p50/p95/p99,
  and on a quiet Linux CI runner as well as a laptop, and must break the cost down (transport hop, SDK
  validation, redaction, storage) before any optimisation is claimed.
- **Bias controls:** dev/test split with the test split frozen before tuning; published third-party
  payloads included where licenses allow; every failure reported.

---

## 7. Threat model (summary — full version in `docs/THREAT_MODEL.md`, Phase 10)

**In scope:** malicious or compromised MCP servers (poisoned definitions, rug-pulls, injected outputs,
sampling abuse), indirect prompt injection via untrusted content, exfiltration via MCP tools.

**Out of scope / known bypasses:** client-native tools (e.g. Claude Code's built-in Bash/WebFetch do not
cross MCP); server processes acting directly on the host (MCPhantom is not a sandbox); same-user
tampering with MCPhantom's files (§1, mitigated, not prevented); behaviour changes behind unchanged
definitions; attribution evasion by URL construction, low-entropy / covert channels, unknown encodings,
embedding evasion (all still subject to Layer 1); over-tainting when a client reuses one connection
across conversations; image/audio content is labeled by source but not inspected.

---

## Change log

- 2026-10-12 — Approved with changes: vertical slice by end of Phase 2; gateway-only v1 (wrap mode
  deferred); storage hardening + same-user tampering in the threat model; bounded provenance memory
  with non-weakening eviction; CEL (`@bufbuild/cel`) chosen over a hand-written parser;
  `better-sqlite3` chosen over `node:sqlite`; no-API-credit operation (Ollama default, Claude Code for
  the demo, Anthropic backend capped at USD 50 with per-batch confirmation); Apache-2.0; benchmark
  named `mcp-attack-bench`; secure defaults with `init` suggestions.
- 2026-10-12 — Phase 3 (static scanner): model-visible text extracted from tools/prompts/instructions
  (name, title, description, every schema description/enum/default/const, annotation titles) and scanned
  for hidden-Unicode smuggling, embedded instructions, tool shadowing, and exfiltration/credential-file
  hints; flagged subjects hidden at list time (config `scan.{enabled,block,mode}`). Tier-1 static
  benchmark (`npm run bench:scanner`) over 35 real official-server tools + 14 synthetic poisoned ones,
  frozen dev/test split, CI-enforced floor. Known bypasses (homoglyph, cross-span, base64, letter-
  spacing) documented and pinned; see `docs/reviews/phase-3.md`.
- 2026-10-12 — Phase 2 follow-ups (owner): A1 fixed — a `write` to a remote URL or outside its declared
  `workspace` (synced/pushed folders included) is treated as `egress` (`src/taint/egress.ts`,
  test-pinned). Showcase plan (Phase 9) now requires the headline demo to use real Claude Code against a
  real poisoned page with a replay fallback, and `npx mcphantom demo` to work from the installed
  package. Repo security settings (secret scanning, push protection, branch protection requiring CI) to
  be enabled once GitHub Pro / Student Pack is active.
- 2026-10-12 — Phase 2 (vertical slice): information-flow labels and a per-connection context label;
  the trifecta invariant (egress/exec while untrusted+secret) enforced by default; exact + normalized
  argument provenance with a two-tier bounded index (Tier A full text FIFO, Tier B identifier hashes
  that survive eviction); secret detection as a taint source; `mcphantom trace`; three demo servers,
  a deterministic injected agent, and a one-command side-by-side demo whose oracle is the attacker's
  own request log. Config gains per-server/-tool classification and `taint.{trifecta,max_index_mb}`.
  Server env default changed to `minimal`. See `docs/reviews/phase-2.md` (finding A1: `write` effect
  not covered by the invariant; A2: test-concurrency flakiness fixed with maxForks).
- 2026-10-12 — Phase 1 review: upstream servers get a `minimal` environment by default (never wider than
  SDK-based clients give them); resource URIs claimed by several servers are hidden and unroutable
  (resource shadowing); HTTP upstream bodies and paginated listings are byte-bounded; HTTP redirects are
  same-origin only. See `docs/reviews/phase-1.md`.
