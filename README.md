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

## What it blocks today

| Threat | What MCPhantom does | Reproduce |
|---|---|---|
| **Lethal-trifecta exfiltration.** Untrusted content steers the agent into sending your secrets out. | Once a session has seen both untrusted and secret data, any `egress`/`exec` call (and any `write` outside its declared workspace) is **denied**. This check never looks at content, so paraphrasing doesn't get past it. | `npm run demo`, `test/demo.e2e.test.ts` |
| **Tool poisoning.** Hidden instructions in tool, prompt or server `instructions` text. | Scanned **before the model sees the list**: invisible Unicode, embedded instructions, shadowing, exfiltration hints, including disguised versions (look-alike characters, base64/hex/URL encoding, letter-spacing, …). A flagged tool is removed from `tools/list`. | `npm run bench:scanner`, `npm run bench:evasion`, `test/scanner.gateway.test.ts` |
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
| Static scanner, held-out split | TPR 100%, FPR 0%, on **14 author-written poisoned + 41 benign** definitions (35 from official servers). Small corpus: a regression floor, not a claim about novel attacks. | `npm run bench:scanner` → [results](bench/results/scanner-bench.md) |
| Layer-2 attribution under evasion | **143/143** claimed transformations caught; **0/39** of the transformations the design says it does not catch; **0/36** false attributions on unrelated benign pairs | `npm run bench:evasion` → [results](bench/results/evasion-bench.md) |
| Scanner under disguise | **90/90** claimed disguises caught | `npm run bench:evasion` |
| Decision latency (laptop, i5-8250U) | p50 1.6 ms (small args), 86 ms (128 KB body) | `npm run bench:policy` → [results](bench/results/policy-bench.md) |
| Proxy overhead per call | low single-digit ms at 1 KB; ~37 ms at 1 MB | `npm run bench:latency` → [results](bench/results/phase1-latency.md) |

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
  `secret`, so a later egress call trips the trifecta invariant on data that was never secret; with
  `internal`, policy rules on `context.confidentiality` start firing. Keep the default `record` unless
  you have measured the rate on your own tools' outputs.
- **Over-tainting.** One untrusted page taints the rest of the connection. A client that reuses one
  connection across conversations stays tainted until MCPhantom restarts. A page that contains a
  fake-looking key makes the context `secret`.
- **`ask` without elicitation is a deny.** There is no approval queue yet (planned for v1).
- **Per-server `may_receive` confidentiality bounds** are in the design but not implemented. Today every
  `tools/call` argument reaches its server unless a rule or the trifecta invariant stops the call.
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

MCPhantom was developed with Claude Code (Anthropic's coding agent) under my design direction and
review. I set the scope, the threat model and the decisions recorded in
[docs/DESIGN.md](docs/DESIGN.md), and reviewed every phase. Each phase ends with a hostile self-review,
published in [docs/reviews/](docs/reviews/). Those reviews are the record: they list the defects found
(including the ones in earlier phases' work), how each was fixed, and which code paths are still
untested.

## Security and contributing

Found a way past a gate that MCPhantom claims to hold? Please report it privately; see
[SECURITY.md](SECURITY.md). Bypasses already listed above can go in a public issue. Development setup
and ground rules: [CONTRIBUTING.md](CONTRIBUTING.md). Changes: [CHANGELOG.md](CHANGELOG.md).

```sh
npm install
npm run check     # lint, typecheck, build, tests
```

License: Apache-2.0. Third-party data notices: [NOTICE](NOTICE).
