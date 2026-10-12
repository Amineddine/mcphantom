# MCPhantom

A security gateway between LLM agents and MCP servers: tool-poisoning and rug-pull detection, taint
tracking across the LLM boundary, and a declarative per-tool policy. Design: [docs/DESIGN.md](docs/DESIGN.md).

> **Status: Phase 2 of 10 — enforces the lethal-trifecta rule; narrow but real.**
> MCPhantom blocks an `egress`/`exec` tool call once a session has taken in both untrusted content and
> secret data, and shows the full taint trace (`mcphantom trace`). It does **not** yet scan tool
> descriptions for poisoning or detect rug-pulls (Phases 3–4), and only exact/normalized provenance
> exists (encoded/paraphrased payloads still block via Layer 1 but are not attributed — Phase 6).
> Reviews: [Phase 1](docs/reviews/phase-1.md), [Phase 2](docs/reviews/phase-2.md). Demo: [docs/DEMO.md](docs/DEMO.md).

## Install and set up

Requires Node ≥ 22.13.

```sh
npm install -g mcphantom        # not published yet; for now: npm install && npm run build && npm link
cd your-project
mcphantom init                  # finds .mcp.json / Claude Desktop / Cursor config, shows a diff, asks
```

See the end-to-end exfiltration demo — unprotected vs. blocked — in [docs/DEMO.md](docs/DEMO.md):

```sh
npm run demo
```

`init` moves your MCP servers into an MCPhantom profile and replaces them with one `mcphantom` entry.
Tools then appear as `<server>__<tool>`. A backup of the original client config is kept, and
`mcphantom uninstall --profile <name>` puts it back.

Run `mcphantom doctor` to see paths, profiles and permission checks.

## Configuration

Profiles live in the MCPhantom config directory (`%APPDATA%\mcphantom` on Windows,
`~/Library/Application Support/mcphantom` on macOS, `~/.config/mcphantom` on Linux):

```yaml
version: 1
servers:
  fs:
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/work"]
  github:
    command: npx
    args: ["-y", "github-mcp"]
    env: { GITHUB_TOKEN: "${GITHUB_TOKEN}" }   # ${VAR} and ${VAR:-default}, as in .mcp.json
  remote:
    type: http
    url: https://mcp.example.com/mcp
    headers: { Authorization: "Bearer ${TOKEN}" }
logging:
  payloads: redacted        # redacted | none | full
retention: { days: 14, max_mb: 256 }
```

Security-relevant defaults:

| Setting | Default | Why |
|---|---|---|
| `env_inherit` | `minimal` | Servers get the SDK's small environment allowlist plus their `env`, never the gateway's full environment. |
| `allow_sampling` | `false` | `sampling/createMessage` lets a server inject text into the model. |
| `logging.payloads` | `redacted` | Credentials are removed *before* anything is written to disk. |
| `security.insecure_permissions` | `fix` | Config, profiles and the event DB are restricted to your user (POSIX `0600`/`0700`; Windows ACL with a single entry for your SID). |

## Measured so far

Overhead per `tools/call` through the gateway on an i5-8250U laptop (Windows 11, Node 22): low
single-digit ms for 1 KB results (within machine noise), ~37 ms for 1 MB results. Method, all runs, and caveats:
[bench/results/phase1-latency.md](bench/results/phase1-latency.md).

## Development

```sh
npm install
npm run check     # lint, typecheck, build, tests
npm run bench:latency
```

License: Apache-2.0.
