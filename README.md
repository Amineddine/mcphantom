# MCPhantom

**A security gateway for MCP that blocks the lethal trifecta even when the model paraphrases. It
measures its own detection and publishes every bypass it knows about.**

![An agent reads a poisoned blog post and tries to send a canary AWS key from .env to an attacker. Without MCPhantom the key reaches the attacker; with MCPhantom the call is blocked and the trace shows why.](docs/demo/demo.gif)

*The verdict in the demo comes from the attacker collector's own request log, not from MCPhantom.
The agent is scripted (no model), so the result shows what the defense does, not what a model happened
to do. Regenerate it: [docs/demo/](docs/demo/).*

> **Status: v0.1, an early release.** Development has been on Windows 11, with CI on Linux, macOS and
> Windows × Node 22/24. Not published to npm yet (planned for v1). Read
> [Known limitations and bypasses](#known-limitations-and-bypasses) before you rely on it.

> **The static scanner, measured independently:** on a pre-registered third-party set, frozen before
> the scanner saw it and run once, it caught **1 of 4** claimed attacks (Wilson 95% CI 4.6–69.9%) and
> **0 of 9** MSB prompt-injection items (0–29.9%); only 1 of 88 poisoned definitions raised any finding
> ([report](docs/reviews/phase-7-heldout.md)). It recognises the phrasings it was built from, not
> injection prose in general. The earlier 100% / 91.7% / 90-of-90 figures below are on author-written
> and derived examples, not held-out performance on real attacks.
>
> **The core protection is the runtime trifecta block, not the scanner.** That rule decides by where
> data came from (context labels), never from the text of an injection, so it does not depend on
> detecting the injection at all; the scanner is a pre-filter on top.

## What it blocks today

| Threat | What MCPhantom does | Reproduce |
|---|---|---|
| **Lethal-trifecta exfiltration.** Untrusted content steers the agent into sending your secrets out. | Once a session has seen both untrusted and secret data, any `egress`/`exec` call (and any `write` outside its declared workspace) is **denied**. This check never looks at content, so paraphrasing doesn't get past it. | `npm run demo`, `test/demo.e2e.test.ts` |
| **Tool poisoning.** Hidden instructions in tool, prompt or server `instructions` text. | Scanned **before the model sees the list**: invisible Unicode, embedded instructions, shadowing, exfiltration hints, including disguised versions (look-alike characters, base64/hex/URL encoding, letter-spacing, …). A flagged tool is removed from `tools/list`. **On a fresh third-party held-out set it caught only 1 of 13 injected descriptions** (see [Measured results](#measured-results)): it recognises the attack phrasings it was built from, not injection prose in general. An injection it misses is still subject to the trifecta rule above. | `npm run bench:scanner`, `npm run bench:evasion`, `npm run bench:heldout`, `test/scanner.gateway.test.ts` |
| **Rug-pulls.** A definition changes after you approved it. | `mcphantom approve` pins model-visible definitions (canonical JSON + SHA-256, HMAC-signed lockfile). Changed or new definitions are hidden, including ones introduced mid-session via `list_changed`. | `test/rugpull.gateway.test.ts`, `mcphantom lock diff` |
| **Unsafe calls by tool.** | Per-tool [CEL](https://cel.dev) rules: `deny` > `ask` > `allow`, with predicates such as `from(arg.to, "untrusted")` (where did this value come from?), `containsSecret(arg)`, `glob`, `within`. Named, audited `declassify` exceptions. `ask` uses MCP elicitation; on clients without it, `ask` is a deny. | `test/policy.gateway.test.ts`, `mcphantom policy explain` |
| **Server-to-model injection.** | `sampling/createMessage` is denied by default (per-server opt-in). Unknown methods are rejected, and any internal error denies the request (fail-closed). | `test/gateway.test.ts` |

Every decision is recorded with its rule, its sources and its evidence (`mcphantom trace`). Payloads
are redacted *before* they reach the event log.

## Quick start

Requires Node ≥ 22.13 and git. v0.1 runs from a checkout (or from the tarball attached to the
GitHub release):

```sh
git clone https://github.com/Amineddine/mcphantom && cd mcphantom
npm install && npm run build
npm run demo                    # unprotected vs. protected, same poisoned page and attacker
npm link                        # puts `mcphantom` on your PATH
mcphantom trace --last --data-dir "<printed by the demo>"
```

From the release tarball instead: `npm install -g ./mcphantom-0.1.0.tgz`. That gives you the
`mcphantom` CLI; the demo needs a checkout until Phase 9.

Protect your own MCP setup:

```sh
cd your-project
mcphantom init                  # finds .mcp.json / Claude Desktop / Cursor config, shows a diff, asks
mcphantom approve --profile <name>   # pin today's tool definitions (enables rug-pull detection)
mcphantom doctor                # paths, profiles, permission checks
```

`init` moves your MCP servers into an MCPhantom profile and replaces them with a single `mcphantom`
entry. A backup of the original config is kept, and `mcphantom uninstall --profile <name>` restores it.
Tools then appear as `<server>__<tool>`. Until `approve` has been run nothing is pinned, so rug-pull
detection is inactive.

## How it works

```
 MCP client ──stdio──► MCPhantom ─┬─► server A   (stdio or Streamable HTTP)
 (Claude Code,          │         └─► server B
  Desktop, Cursor)      ├─ 1 definition gate   scan + pin check → filters tools/list before the model sees it
                        ├─ 2 call gate         context label + argument provenance + CEL policy → allow / ask / deny
                        └─ 3 output gate       label the output, detect secrets, index it for provenance
```

MCPhantom sees tool outputs entering the model and tool arguments leaving it. It never sees the model's
context or reasoning, so it cannot prove that data did **not** pass through the model. That is why it
works in two layers with different jobs:

- **Layer 1: context labels (sound).** Every output gets an integrity label (`trusted ⊑ untrusted`)
  and a confidentiality label (`public ⊑ internal ⊑ secret`). The session's label only ever rises. Once
  it is both untrusted and secret, egress is denied unless a named `declassify` entry allows it. This
  layer never inspects content, so paraphrase and encoding cannot get around it. The price is
  over-tainting, i.e. false blocks.
- **Layer 2: argument provenance (precise, evidence only).** For each string in a call's arguments,
  MCPhantom asks which earlier output it came from. Matchers: exact, normalized (case, NFKC, zero-width,
  confusables), decoded (base64, hex, URL, entities, escapes, rot13, reversal, separator spelling,
  chains up to depth 3), fuzzy (winnowing fingerprints) and cumulative (a secret split across calls).
  The idea behind it: the parts of an exfiltration that matter, the attacker's address and the secret,
  are high-entropy identifiers that must cross the model *exactly*, or the attack fails.
  **Honesty rule:** Layer-2 evidence can add a restriction, explain a decision, or satisfy an allow rule
  you wrote. Finding no match is never treated as proof that nothing flowed. Allow rules and declassify
  conditions count only deterministic evidence (exact/normalized/decoded), never fuzzy similarity.

Full design, threat model and decisions: [docs/DESIGN.md](docs/DESIGN.md).

## Configuration

Profiles live in the MCPhantom config directory (`%APPDATA%\mcphantom` on Windows,
`~/Library/Application Support/mcphantom` on macOS, `~/.config/mcphantom` on Linux):

```yaml
version: 1
servers:
  web:
    command: uvx
    args: ["mcp-server-fetch"]                   # the reference fetch server
    defaults: { integrity: untrusted }            # a third party controls what it returns
  fs:
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/work"]
    tools:
      read_file: { effect: read, integrity: trusted }
      write_file: { effect: write, workspace: /work }   # a write outside /work counts as egress
  mail:
    type: http
    url: https://mcp.example.com/mcp
    headers: { Authorization: "Bearer ${TOKEN}" }  # ${VAR} and ${VAR:-default}, as in .mcp.json
    tools:
      send_email:
        effect: egress
        rules:
          - deny: 'from(arg.to, "untrusted")'      # recipient copied from untrusted content
          - deny: 'containsSecret(arg)'
          - ask:  'context.integrity == "untrusted"'
declassify:
  - id: own-inbox
    tool: mail__send_email
    when: 'arg.to == "me@corp.example"'
    reason: "My own inbox; accepted risk"
```

Anything you don't classify is treated as `egress` with `untrusted` output. `mcphantom suggest` proposes
classifications from server annotations and tool names. Those annotations are claims made by the server,
so a suggestion looser than the secure default needs `--accept-loose`. `mcphantom policy lint` checks
your rules against the live tool schemas.

Security-relevant defaults:

| Setting | Default | Why |
|---|---|---|
| `taint.trifecta` | `deny` | `log` is audit mode, which the unprotected half of the demo uses. |
| `scan.block` / `scan.mode` | `medium` / `hide` | Flagged definitions never reach the model. |
| `secrets.entropy.on_hit` | `record` | What a possible secret (random-looking, no known format) in a tool output does to the session label: `record` (log only), `internal`, or `secret`. Identifier-shaped values (hex, UUIDs, digests, type-prefixed ids, values of id-named fields) never raise it. ⚠ `internal`/`secret` cause false blocks: 9.2% of benign outputs are flagged (see Known limitations). |
| `secrets.entropy.redact` | `true` | Redact possible secrets in the event log too. |
| `servers.<id>.may_receive` | unset | The most confidential data this server may receive in tool-call arguments: `public`, `internal` or `secret`. |
| `servers.<id>.may_receive_mode` | `evidence` | `evidence`: deny when an argument carries a credential or comes, per Layer 2, from data above the bound. `context`: also deny whenever the session holds such data (sound, blocks more). |
| `rugpull.mode` / `on_bad_signature` | `enforce` / `refuse` | A tampered or malformed lockfile stops startup instead of disabling the check. |
| `env_inherit` | `minimal` | Servers get the SDK's small environment allowlist plus their own `env`, never the gateway's full environment. |
| `allow_sampling` | `false` | `sampling/createMessage` lets a server put text straight into the model. |
| `logging.payloads` | `redacted` | Credentials are removed *before* anything is written to disk. |
| `logging.on_failure` | `warn` | `deny` makes the audit log a control: a request (tool call, prompt, resource read or subscription, completion, relayed server request) that can't be logged before it is forwarded is refused, and a result that can't be logged is withheld. |
| `resources.unrouted` | `deny` | A resource URI that no server listed is refused. |
| `security.insecure_permissions` | `fix` | Config, profiles and the event DB are restricted to your user (POSIX `0600`/`0700`; on Windows an ACL with a single entry for your SID). |

## Measured results

All numbers are deterministic, model-free and regenerated by the command shown. Methodology and every
miss are in the linked files.

| What | Result | Command |
|---|---|---|
| **Static scanner — independent third-party set** (pre-registered, frozen with a SHA-256 manifest, run once; the headline scanner number) | **1/4** claimed description injections from MCPSecBench caught (Wilson 95% CI 4.6–69.9%); **0/9** MSB prompt injections, placed by MSB's own (disabled) insertion code (0–29.9%), reported separately; 0/75 of the kinds outside the claims. **Only 1 of 88 items raised any finding.** The scanner misses common third-party injection wording (e.g. an `<INFORMATION>` block "from the user" asking for a file write). Not tuned on; the fix needs new dev examples first and a fresh set to measure it. | `npm run bench:heldout` → [results](bench/results/heldout-7.md) |
| Static scanner on **author-written and derived examples** (internal test split; not held-out performance on real attacks) | TPR 100% (12/12), FPR 0% (0/132), after one tuning round on the dev split; before it, 91.7% / 0.8%. The test split had already been seen before that round. Corpus: **260 benign** definitions (248 real: official reference servers, GitHub's and Microsoft Playwright's MCP servers) and **27 poisoned** (22 author-written, 5 rewritten from published third-party attacks, all 5 held out). Every model-visible schema field is scanned, parameter names included. A regression floor, not a claim about novel attacks. | `npm run bench:scanner` → [results](bench/results/scanner-bench.md) |
| Static scanner on PostHog's published MCP tool catalog | 5 of 1,121 tools hidden (0.4%), all false positives of MCPhantom's; coverage stated exactly (descriptions/titles/annotations of all tools, 43 input schemas). See [docs/posthog.md](docs/posthog.md). | `npm run bench:posthog` → [results](bench/results/posthog-scan.md) |
| Runtime benchmark, Tier 1 (`mcp-attack-bench`, recorded traces replayed through the gate; author-written, a regression floor) | MCPhantom at defaults: **0/60** claimed exfiltration attacks succeed (5 channels × 6 encodings × 2 secret formats; Wilson 0–6.0%), 2 partial leaks (2 of 3 fragments of a split secret reached a `may_receive`-bounded sink server before the block); no defense / scanner only 60/60, deny-all-egress 24/60. False blocks **4/15** benign traces — all four the deliberately over-tainted case. Outside the claims: an unbounded sink server and a secret in the URL of a tool classified `read` get through (8/8). Black-box check through the real gateway on the demo fixtures in CI. | `npm run bench:runtime` → [results](bench/results/runtime-bench.md), [spec](docs/benchmark.md) |
| Baselines and ablations (pre-registered; same traces plus a `from()` policy family and an unclassified-source family) | Layer 2 changes **no trifecta decision** (the invariant reads Layer-1 labels); it decides `may_receive` and `from()` rules. Layer 1 only: 7/60 claimed attacks succeed (all to the bounded sink server) and 4/5 policy-family attacks on internal data succeed; one declassified benign trace becomes a false block. Trifecta in audit mode: 48/60. `may_receive_mode: context`: 0 partial leaks, 6/15 false blocks. Entropy `on_hit: secret` stops 3/3 random secrets from an unclassified source at 1/3 false blocks. | `npm run bench:ablations` → [results](bench/results/ablations.md), [review](docs/reviews/phase-7-ablations.md) |
| Layer-2 attribution under evasion | **143/143** claimed transformations caught; **0/39** of the transformations the design says it does not catch; **0/36** false attributions on unrelated benign pairs | `npm run bench:evasion` → [results](bench/results/evasion-bench.md) |
| Scanner under disguise (author-written examples) | **90/90** claimed disguises caught | `npm run bench:evasion` |
| Proxy overhead per call (pre-registered; GitHub-hosted Linux VMs, 3 × 10 launches, bootstrap 95% CIs; shared VMs, variance reported) | gateway − direct p50: **+5 ms** at 1 KiB with payload logging off; **+37 ms** at 64 KiB; **+119 ms** at 1 MiB (laptop: +248 ms). At 1 MiB, 59% of the cost is indexing the output; the SDK's parsing and validation is about 4%. A real server (`server-filesystem`, 64 KiB file): +42 ms. | `npm run bench:perf` → [results](bench/results/perf.md), [review](docs/reviews/phase-7-perf.md) |
| Decision latency, in process (same VMs) | p50 0.3 ms (small args); 24 ms (128 KB body); 39 ms (slash-heavy 128 KB, 0/3,000 deadline denials); 11 ms for a short body once the 32 MiB index is full | `npm run bench:perf` |
| Memory and eviction (same VMs) | Tier A never exceeds its budget; RSS ≈ 200 MiB at 32 MiB after 4,000 calls. Under eviction at any budget, 0/60 claimed suite attacks succeed, and partial leaks fall to 0 (fail-closed), at +2 false blocks. **An identifier flood followed by eviction defeats `from()` deny rules: 4/5 policy-family attacks succeed** (see Known limitations). | `npm run bench:perf -- --parts eviction` → [results](bench/results/eviction.md) |

**Real-world reference: PostHog's MCP server.** What PostHog already does well, what MCPhantom adds,
the "untrusted event data" scenario and the catalog scan: [docs/posthog.md](docs/posthog.md).

These suites are written by the author, so they measure the attacks we thought of. Live attack-success
rates against real models (and an AgentDojo-style evaluation) are not measured yet; that is Phase 9.

## Known limitations and bypasses

MCPhantom is defence-in-depth at the MCP boundary. It is not a sandbox, and it is not a proof that your
agent is safe.

- **Only MCP traffic is seen.** A client's built-in tools (Claude Code's Bash, WebFetch, file edits)
  never cross MCP, so an injected agent can exfiltrate through them. (Planned for v1: a Claude Code
  `PreToolUse` hook.)
- **Not a sandbox.** An upstream server process can act directly on the host: files, network, anything
  its OS user can do. Run untrusted servers under another user, in a container or in a sandbox.
- **Same-user tampering is mitigated, not prevented.** The lockfile HMAC stops other OS users from
  editing pins and detects corruption. A malicious server running as *your* user can read the key and
  re-sign. Lockfile and policy are read once at startup, which narrows the window to a restart.
- **Behaviour changes behind an unchanged definition** are not detectable by pinning.
- **Resource definitions are not pinned yet** (tools, prompts and server instructions are).
- **Layer-2 bypasses (published, pinned by tests):** encodings not decoded (decimal character codes,
  caesar shifts, NATO spelling, interleaved junk, multi-character gaps), pieces sent out of order or to
  different tools, paraphrase, and URL construction. **Scanner bypasses:** filler words inside an
  instruction, leetspeak, translation, decimal codes, base64 split across properties. Full list:
  [bench/results/evasion-bench.md](bench/results/evasion-bench.md). All of them still run into Layer 1,
  which doesn't look at content.
- **Layer 1 only guards data labelled `secret`.** Exfiltration of data that never got that label is not
  blocked by the invariant: `internal` files you didn't classify as secret, or a secret the detectors
  missed. You can still add per-tool rules for those cases.
- **Secrets are detected by known formats and keywords**, plus policy-declared sources. A random value
  with no known format and no keyword is only a *possible* secret: an entropy detector redacts it in
  the log and records it, but by default it does not make the session `secret`, because it can't tell
  a key from a random id. Hex secrets, an unknown vendor's prefixed keys, a secret stored under an
  id-named field, human-chosen passwords and other low-entropy secrets are not detected as random at
  all (detection 78.0% of generated secrets, held-out split, `npm run bench:entropy`).
- **⚠ `secrets.entropy.on_hit: internal` or `secret` will cause false blocks.** On benign tool outputs
  the detector still flags **9.2%** of them (6 of 65, held-out split) — random user ids in log lines,
  analytics result rows, e-mail local parts. With `on_hit: secret`, each such output makes the session
  `secret`, so a later egress call trips the trifecta invariant on data that was never secret, and
  servers with `may_receive` below `secret` in `context` mode start refusing calls; with `internal`,
  `may_receive: public` servers in `context` mode and policy rules on `context.confidentiality` start
  firing. Keep the default `record` unless you have measured the rate on your own tools' outputs.
- **Over-tainting.** One untrusted page taints the rest of the connection. A client that reuses one
  connection across conversations stays tainted until MCPhantom restarts. A page that contains a
  fake-looking key makes the context `secret`.
- **`ask` without elicitation is a deny.** There is no approval queue yet (planned for v1).
- **What a server receives is bounded only if you set `may_receive` on it.** Unset, every `tools/call`
  argument reaches its server unless a rule or the trifecta invariant stops the call — and the trifecta
  only guards `egress`/`exec` tools, so a server whose "read-only" tool simply keeps what it is sent is
  not covered. In the default `evidence` mode the bound catches credentials and data Layer 2 can
  attribute; an encoding it doesn't decode gets through (`may_receive_mode: context` closes that, at the
  cost of blocking that server once such data was read).
- **`evidence` mode fails closed where attribution cannot look, but not everywhere.** Credentials are
  searched in full in every argument field. Once the session holds data above a server's bound, a call
  to it is denied if it is too big for attribution to check (a field over 64 KiB, more than 512 fields,
  over 128 KiB of text to decode) or if attribution lost track of such data earlier (an evicted or
  partly decoded output); the reason names the bound and the way out. Two bounds do **not** block, by
  design: an *edited* copy of confidential prose in a field over 8 KiB, and a value split across calls
  to one tool with more than 16 KiB sent in between, both get through evidence mode. What each
  alternative would cost in false blocks: `npm run bench:may-receive`.
- **A secret split across calls to a bounded server leaks in part before the block.** The cumulative
  matcher can only attribute the call that *completes* the secret, so in evidence mode 2 of 3 fragments
  reach the server first (2 partial leaks in the runtime benchmark). `may_receive_mode: context` closes
  it (0 fragments, measured), but blocks every call to that server once the session holds anything
  above the bound — and outputs of tools with no confidentiality set count as `internal`, so on a
  `may_receive: public` server one unclassified read is enough (2 extra false blocks on the benchmark's
  2 benign sink-server traces). Measured in `npm run bench:ablations`.
- **An untrusted source can evict the evidence a `from()` rule needs.** Tier B (identifier hashes) never evicts
  and silently drops new identifiers once full. An attacker-controlled source that first floods it (≈ 111k
  distinct tokens), then fills Tier A, leaves `from(arg.to, "untrusted")` no evidence. Such a rule is
  precision-mode, so it does not fail closed: 4 of 5 policy-family attacks on `internal` data succeed in the
  eviction benchmark, at every budget. The trifecta check and `may_receive` are unaffected (0/60). Measured in
  `npm run bench:perf -- --parts eviction`; a fix is open (review R7p-3).
- **Large outputs are slow.** At 1 MiB the gateway adds about 120 ms per call on a CI VM, about 250 ms on a 2017
  laptop, mostly indexing the output. Decisions slow down as the index fills: 82 ms for an 8 KiB argument with
  a full 32 MiB index.
- **Images and audio** are labelled by their source but not inspected.
- **Large inputs fail closed.** Policy evaluation has a 50 ms deadline; an extreme call (≈ 4000 fields
  on a slow machine) can be denied.
- **Single machine, one developer.** Local testing has been on Windows 11 only; Linux and macOS are
  exercised by CI only.

Each phase's hostile self-review lists what is *not* tested: [docs/reviews/](docs/reviews/).

## Related work

MCPhantom borrows its core ideas from this work. Where it stands relative to each:

- **Simon Willison, ["The lethal trifecta for AI agents: private data, untrusted content, and external
  communication"](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)** (June 2025). He named
  the condition. MCPhantom's default invariant is that condition, enforced: egress while the context is
  untrusted *and* secret.
- **CaMeL: Debenedetti et al., ["Defeating Prompt Injections by Design"](https://arxiv.org/abs/2503.18813)**
  (Google DeepMind / ETH Zürich, 2025). A privileged LLM writes a program from the trusted user query, a
  quarantined LLM parses untrusted data, and a custom interpreter tracks data flow and checks capability
  policies before each tool call. Because CaMeL controls the agent loop, it can give much stronger
  guarantees than a gateway can. MCPhantom doesn't change the agent at all and sits at the MCP boundary.
  It never sees the model's context, so its sound layer has to over-taint where CaMeL can track flow
  precisely. Both share the honest cost of policies that someone has to write.
- **FIDES: Costa et al., ["Securing AI Agents with Information-Flow Control"](https://arxiv.org/abs/2505.23643)**
  (Microsoft, 2025). A planner that carries confidentiality and integrity labels and enforces policies
  deterministically, with mechanisms to hide information from the planner. MCPhantom's Layer 1 uses the
  same kind of lattice. The difference is placement: FIDES is built into the planner; MCPhantom labels
  from outside, at the tool boundary, which is weaker but can be inserted in front of an unmodified
  client.
- **AgentDojo: Debenedetti et al., ["AgentDojo: A Dynamic Environment to Evaluate Prompt Injection
  Attacks and Defenses for LLM Agents"](https://arxiv.org/abs/2406.13352)** (NeurIPS 2024 Datasets and
  Benchmarks). The standard benchmark for utility and attack success under injection. MCPhantom does
  **not** report AgentDojo results yet. Its benchmarks so far are deterministic and author-written;
  live-model evaluation is Phase 9.
- **Invariant Labs, ["MCP Security Notification: Tool Poisoning
  Attacks"](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)** (April
  2025). Describes tool poisoning, rug-pulls and tool shadowing, and recommends pinning definitions with
  checksums. MCPhantom's definition gate implements those recommendations at list time.
- **MCP scanners.** Invariant Labs' [MCP-Scan](https://invariantlabs.ai/blog/introducing-mcp-scan) (the
  repository is now [snyk/agent-scan](https://github.com/snyk/agent-scan)) scans the agents, servers
  and tool descriptions installed on a machine. Static scanning is MCPhantom's first gate too. What
  MCPhantom adds is runtime enforcement on data flow across calls.
- **MCP gateways.** [Docker MCP Gateway](https://github.com/docker/mcp-gateway) runs servers in
  containers with managed secrets. That isolation is exactly the boundary MCPhantom lacks, and the two
  combine. [Lasso MCP Gateway](https://github.com/lasso-security/mcp-gateway) offers plugin guardrails
  (secret/PII masking, description scanning, an optional hosted prompt-injection check). MCPhantom's
  focus is different: deterministic, local information-flow enforcement whose detection is measured and
  whose bypasses are published.

If MCPhantom misrepresents your work, please open an issue.

## How this was built

**Designed, directed and reviewed by me (Amineddine Znin); implemented with Claude Code** (Anthropic's
coding agent).

- **Design and direction (me):** scope, threat model, architecture and every decision on what is claimed,
  measured, published or deferred. Each decision is logged with its date, the options considered and my
  reason in [docs/decisions.md](docs/decisions.md); the design is [docs/DESIGN.md](docs/DESIGN.md).
- **Implementation (Claude Code):** the code, tests, benchmarks and first drafts of the docs, built phase
  by phase against that design.
- **Review (me):** I review every phase and pull request, and every merge waits for my confirmation. Each
  phase also ends with a hostile self-review in [docs/reviews/](docs/reviews/), listing the defects found
  (including those in earlier phases' work), how each was fixed and which code paths are still untested.
  From Phase 7 item 4 on, each review ends with an "Owner review" section: my verdict, what I changed or
  overrode, and the risks I accept.

Walkthrough video: coming soon.

## Security and contributing

Found a way past a gate that MCPhantom claims to hold? Please report it privately; see
[SECURITY.md](SECURITY.md). Bypasses already listed above can go in a public issue. Development setup
and ground rules: [CONTRIBUTING.md](CONTRIBUTING.md). Changes: [CHANGELOG.md](CHANGELOG.md).

```sh
npm install
npm run check     # lint, typecheck, build, tests
```

License: Apache-2.0. Third-party data notices: [NOTICE](NOTICE).
