# PostHog MCP tool catalog: static scan (`npm run bench:posthog`)

Source: PostHog/posthog@61a8655 services/mcp/schema (MIT), imported by `bench/corpus/import-posthog.mjs`. Scanner settings: defaults (block at medium).

## Coverage (exact)

- **1121 tool definitions**: name, title, description and annotations of every tool in `tool-definitions-all.json`.
- **Input schemas: 43 published definitions** (`tool-inputs.json`). Only `ExecuteSQLSchema` is attached to its tool (`execute-sql`, confirmed from source); the other 42 are scanned as standalone schemas because the published files do not say which tool uses them. Tools with a scanned schema: 1.
- **Not covered:** the input schemas of the other tools (generated at build time, not published there), other catalog metadata fields (summary, prompt hints) whose model visibility was not verified, and anything served at runtime. No PostHog service was contacted; nothing under `ee/` was read.

## Result

- Tools MCPhantom would **hide** at default settings: **5 of 1121 (0.4%)**. Each is a false positive of MCPhantom's (PostHog is the vendor), listed below.
- Standalone schemas flagged: 0 of 42.
- Tools with only low-severity findings (recorded, still shown): 15.

| finding (severity) | count |
|---|---|
| embedded-instruction (low) | 12 |
| tool-shadowing (high) | 4 |
| exfiltration-hint (low) | 3 |
| embedded-instruction (medium) | 1 |

## Hidden tools (false positives) — every one

- `error-tracking-symbol-sets-list` — tool-shadowing (high) in `description`: description redefines the behaviour of another tool ('download')
- `experiment-create` — tool-shadowing (high) in `description`: description redefines the behaviour of another tool ('this')
- `experiment-ship-variant` — tool-shadowing (high) in `description`: description redefines the behaviour of another tool ('this')
- `marketing-analytics-diagnose` — tool-shadowing (high) in `description`: description redefines the behaviour of another tool ('this')
- `mcp-connection-tools-list` — embedded-instruction (medium) in `description`: instruction to the model to invoke or feed another tool

## Flagged standalone schemas

None.

## Low-severity findings (recorded, not hidden)

- `cdp-functions-create` — exfiltration-hint (low) in `description`: description directs sending data to an external destination
- `dashboard-create-tile` — exfiltration-hint (low) in `description`: description directs sending data to an external destination
- `docs-search` — exfiltration-hint (low) in `description`: description directs sending data to an external destination
- `experiment-update` — embedded-instruction (low) in `description`: imperative directed at the model
- `llma-evaluation-backfill-create` — embedded-instruction (low) in `description`: addresses the model as an AI
- `logs-attribute-values-list` — embedded-instruction (low) in `description`: imperative directed at the model
- `logs-attributes-list` — embedded-instruction (low) in `description`: imperative directed at the model
- `notebooks-partial-update` — embedded-instruction (low) in `description`: imperative directed at the model
- `query-funnel` — embedded-instruction (low) in `description`: imperative directed at the model
- `query-logs` — embedded-instruction (low) in `description`: imperative directed at the model
- `read-data-schema` — embedded-instruction (low) in `description`: imperative directed at the model
- `session-recording-playlist-update` — embedded-instruction (low) in `description`: imperative directed at the model
- `view-update` — embedded-instruction (low) in `description`: imperative directed at the model
- `workflows-create` — embedded-instruction (low) in `description`: imperative directed at the model
- `workflows-schedule-create` — embedded-instruction (low) in `description`: imperative directed at the model
