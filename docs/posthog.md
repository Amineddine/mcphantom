# MCPhantom and PostHog's MCP server

What I tested, what PostHog's server already does well, what MCPhantom adds, and the limits of both.
Everything here is reproducible from this repository; nothing was run against PostHog's services.

## Summary

I build MCPhantom, an open-source security gateway that sits between an AI agent and the MCP servers it
uses. I used PostHog's MCP server as a real-world reference, working only from PostHog's public,
MIT-licensed source and tool catalog (commit `61a8655`) and a local test fixture — no traffic to
PostHog's services and no testing of their infrastructure.

**The scenario is a generic MCP risk, not a PostHog vulnerability.** Analytics data is partly written by
third parties: anyone holding a project's public token can set event properties. When an agent runs
`execute-sql`, those property values enter the model's context alongside trusted data. If the agent also
has a secret in context and a tool that can send data out, that is the "lethal trifecta" every agent with
tools faces, whichever server the untrusted text comes from.

**What PostHog already does well:** project-scoped "MCP Server" API keys and OAuth; a read-only mode; tool
filtering by feature or name; project pinning to limit blast radius; a clear prompt-injection warning in
the docs; and honest tool annotations — `execute-sql` is marked `openWorldHint: true`, which correctly
tells clients its output can contain outside content.

**What MCPhantom adds on top:** it uses that `openWorldHint` to label `execute-sql` results as untrusted,
then tracks that label across tools. In my deterministic test, once a query result and a secret were both
in the session, an attempt to post the secret to an outside webhook was blocked; with an optional policy
rule, a write back into PostHog (`annotation-create`) after reading untrusted data required the user's
confirmation and was refused without it. With MCPhantom in audit mode, both actions went through — the
test shows the risk is real and the block is MCPhantom's.

**Static scan of PostHog's 1,121 published tool definitions:** MCPhantom would hide 5 of them (0.4%) at
its default settings. All 5 are false positives on my side — three come from a flaw in one of my rules
that I am fixing — and nothing in the catalog looked like tool poisoning. Corrections from PostHog are
welcome via an issue.

## What I tested

| Part | How | Status |
|---|---|---|
| Static scan of the tool catalog | `npm run bench:posthog` over `services/mcp/schema/` at `61a8655` | [results](../bench/results/posthog-scan.md) |
| "Untrusted event data" scenario | `test/posthog-scenario.e2e.test.ts`, in CI | 6 tests |
| PostHog's real server against a mock backend | planned | not done yet |
| Live LLM runs, false-block rate on normal workflows | planned | not done yet |

### The scenario

A scripted agent (no model) issues tool calls directly; the third-party content is an inert placeholder
string, no injection text. The fixture serves PostHog's exact published `execute-sql` definition and the
response envelope PostHog's server returns to a generic client (one text block, no structured content).
The row text inside is a plain table: PostHog's backend renderer is under `ee/` (enterprise licence) and I
deliberately did not read it.

| Sequence | Unprotected (MCPhantom audit mode) | Protected (defaults) |
|---|---|---|
| `execute-sql` → read a secret → post it to a webhook | secret reaches the collector | **blocked** (trifecta invariant); the decision names `ph__execute-sql` as the untrusted source |
| `execute-sql` → `annotation-create` with query-derived text | annotation written | **blocked** by a policy `ask` on the write tool (no elicitation in the test client → deny) |

The second row needs a policy rule: with no secret in context the trifecta does not apply, so
integrity-only attacks (writing attacker-influenced content) are covered only where a rule says so.

Classification used: `execute-sql` as `read` with untrusted output — what `mcphantom suggest` proposes from
PostHog's own annotations (`openWorldHint` → untrusted, server-claimed; `readOnlyHint` → read, which is
looser than MCPhantom's secure default and needs `--accept-loose`).

### The static scan

**Coverage, exactly:** name, title, description and annotations of all **1,121** tools; **43** published
input-schema definitions, of which only `ExecuteSQLSchema` could be attached to its tool from the published
files (the other 42 were scanned as standalone schemas). The input schemas of the other tools are
generated at build time and were not covered.

**Result:** 5 hidden (0.4%), all false positives of MCPhantom's: three where my tool-shadowing rule reads
"this tool" as a reference to another tool (a self-reference flaw I already fixed in a sibling rule and
will fix here in the next tuning round), one "download" read as a tool name, and one routing instruction.
15 more tools have low-severity findings that are recorded but not acted on. No schema was flagged. Full
list: [bench/results/posthog-scan.md](../bench/results/posthog-scan.md).

## Rules I followed

PostHog's Bugcrowd brief (dated 2025-09-10) lists `us.posthog.com`, `posthog.com` and the two GitHub
repositories as in scope; `mcp.posthog.com` is not listed, so I did not test it. No adversarial or
injection work touched any PostHog service; the scenario runs entirely on local fixtures. Anything that had
looked like a vulnerability in PostHog itself would have gone to private disclosure, not here.
