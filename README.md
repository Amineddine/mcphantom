# MCPhantom

A security gateway between LLM agents and MCP servers: tool-poisoning and rug-pull detection, taint
tracking across the LLM boundary, and a declarative per-tool policy. Design: [docs/DESIGN.md](docs/DESIGN.md).

> **Status: Phase 1 of 10 — transparent gateway only. MCPhantom does not detect or block attacks yet.**
> What works today: one gateway in front of many MCP servers (stdio and Streamable HTTP), namespaced tools,
> an owner-only, secret-redacted audit log, fail-closed handling of unknown methods, server sampling
> denied by default, and `init`/`uninstall` for Claude Code, Claude Desktop and Cursor configs.
> See [the Phase 1 review](docs/reviews/phase-1.md) for known weaknesses.

## Install and set up

Requires Node ≥ 22.13.

```sh
npm install -g mcphantom        # not published yet; for now: npm install && npm run build && npm link
cd your-project
mcphantom init                  # finds .mcp.json / Claude Desktop / Cursor config, shows a diff, asks
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
