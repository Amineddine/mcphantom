# MCP SDK progress/response race (AUD-10b)

**Status (2026-10-13): reported upstream.** The bug was already tracked as
[modelcontextprotocol/typescript-sdk#2580](https://github.com/modelcontextprotocol/typescript-sdk/issues/2580),
so instead of opening a new issue the owner posted our root cause and deterministic repro there:
[comment on #2580](https://github.com/modelcontextprotocol/typescript-sdk/issues/2580#issuecomment-6156241420).
An open upstream PR, [#2586](https://github.com/modelcontextprotocol/typescript-sdk/pull/2586) (by another
contributor), proposes ignoring late progress for recently completed tokens.

Files here are the working drafts behind that comment, kept as the record:

- [`ISSUE.md`](ISSUE.md): the analysis (cause: deferred notification dispatch vs. synchronous response
  handling). It was not filed as a new issue.
- [`repro.mts`](repro.mts): deterministic reproduction; `PATCHED=1` applies the candidate fix. Re-run
  on 2026-10-13 against SDK 1.32.1: unpatched `{"seen":[],"errors":["…unknown token…"]}`, patched
  `{"seen":[1],"errors":[]}`.
- [`PR.md`](PR.md): our candidate fix. **Not opened, and not ready**: applied naively it breaks two
  task-progress tests in `test/shared/protocol.test.ts`.

MCPhantom's own handling is unchanged: the gateway cannot fix this without SDK internals, so tests do
not assert the final progress message (DESIGN.md, AUD-10).
