# Phase 6.5 review — v0.1 release preparation

Scope: the rewritten README (claims, limitations, related work, how this was built), the demo GIF
tooling (`docs/demo/demo.tape`, `.github/workflows/demo-gif.yml`), SECURITY.md, CONTRIBUTING.md, issue
templates, CHANGELOG.md, and a publish-safety audit of the whole history. No product code changed.

## Method

Every row of the README's "What it blocks today" table and every limitation was checked against the
code or a test. Every Related-work reference was checked against its primary source (arXiv abstract or
full text, the author's post, the project's repository) on 2026-10-13. Nothing was cited from memory.
The audit covered `git log -p --all` (every blob on every branch), not just HEAD.

## Findings

| # | Severity | Finding | Disposition |
|---|---|---|---|
| R6.5-1 | **Medium (fixed)** | The first README draft's configuration example used a placeholder package with `npx -y some-fetch-server`. A reader who copies it runs whatever anyone later publishes under that name, a supply-chain trap in a security tool's own docs. | Replaced with the reference fetch server (`uvx mcp-server-fetch`). Every other command in the README names a real package or a `*.example` host. |
| R6.5-2 | **Medium (fixed)** | **An unstated limit of Layer 1.** No earlier doc said plainly that the trifecta invariant only guards data labelled `secret`. Exfiltration of unclassified `internal` data, or of a secret the detectors miss, is not blocked by it. | Stated in the README's limitations, with the per-tool-rule workaround. |
| R6.5-3 | Medium (fixed) | **DESIGN.md described two things that do not exist:** a CLI "reload with a diff" for the lockfile/policy (§1; in fact they are read once and only a restart reloads them), and per-server `may_receive` (§2), which was never implemented. | Both corrected in DESIGN.md and stated in the README. `may_receive` is not scheduled in §5. **Owner to place it.** |
| R6.5-4 | Medium (accepted, owner) | **Moving `docs/upstream/` out of the tree does not unpublish it.** The SDK-race drafts are in commits `7f97b31` and `96d7327`, so making the repository public publishes them through history. | Acceptable only because the owner files the SDK issue before the repo goes public (owner decision). Rewriting history would need a force push, which is denied by policy. Re-check the order on release day. |
| R6.5-5 | Low (fixed) | The README status said "Phase 5 of 10"; the DESIGN resume point said 6a CI had not run. | Updated. |
| R6.5-6 | Low (accepted) | The packed tarball ships `dist/**/*.js.map` that point to `../src/*.ts`, which is not shipped. The maps are dangling but leak nothing (relative paths, no `sourcesContent`, no local paths; checked). | Revisit at v1 packaging: ship `src` or drop the maps. |
| R6.5-7 | Low (accepted) | `package.json` keeps a `prepare` script (`scripts/install-hooks.mjs`, not in the tarball). npm does not run `prepare` for tarball installs. A git-URL install runs it inside the clone, where the script exists and does nothing outside its own checkout. | Accepted. Tarball install tested from a fresh prefix (`mcphantom --version` OK). |
| R6.5-8 | Low (accepted) | The GIF shows random loopback ports, so renders differ byte-for-byte. | Documented in `docs/demo/README.md`; everything else is deterministic. |

## Related-work verification (primary sources)

| Reference | Checked | Notes |
|---|---|---|
| Willison, "The lethal trifecta for AI agents: private data, untrusted content, and external communication", 2025-06-16 | Title, date, the three elements | — |
| Debenedetti et al., "Defeating Prompt Injections by Design" (CaMeL), arXiv 2503.18813 | Title, authors, P-LLM/Q-LLM + custom interpreter, stated policy burden | The README states only CaMeL's architecture and its own stated cost; no utility number is quoted. |
| Costa et al., "Securing AI Agents with Information-Flow Control" (FIDES), arXiv 2505.23643 | Title, authors, labels + deterministic enforcement in the planner | Affiliation (Microsoft) is not on the abstract page; it comes from the author list (e.g. Russinovich, Köpf, Paverd). |
| Debenedetti et al., "AgentDojo …", arXiv 2406.13352, NeurIPS 2024 D&B | Title, authors; venue from the authors' BibTeX | The NeurIPS accepted-papers page was not checked directly. |
| Invariant Labs, "MCP Security Notification: Tool Poisoning Attacks", 2025-04-01 | Title, date, poisoning/rug-pull/shadowing, pinning recommendation | — |
| MCP-Scan → `snyk/agent-scan` | The `invariantlabs-ai/mcp-scan` URL now serves `snyk/agent-scan`; README describes current scope (scanning installed agents, servers, skills) | The README says "the repository is now", not "renamed". |
| Docker MCP Gateway, Lasso MCP Gateway | READMEs: container isolation and secrets; plugin guardrails, description scanning, optional hosted check | Described from their own READMEs, no capability claims beyond them. |

Positioning: no "first" or "only" claims. Where a related system is stronger (CaMeL, FIDES), the README
says so and explains why.

## Publish-safety audit

- **gitleaks 8.30.1** (checksum-verified), `git --log-opts=--all`: 28 commits, no leaks. Rerun after the
  final commit: see the release checklist.
- **Personal data in all history:** no personal paths, no personal e-mail. Commit authors use the
  GitHub noreply address. Every e-mail address in the content is `*.example` / `*.internal` test data.
- **External hosts in all history:** only registries, standards bodies, cited sources, and one
  `hooks.slack.com/services/...` placeholder in the benign corpus (no token). Attack payloads target
  `*.example` hosts or loopback.
- **Attack payloads read in full** (`src/demo/world.ts`, `bench/corpus/malicious.json`,
  `bench/corpus/build-malicious.mjs` output, fixtures). They are toy injections aimed at loopback or
  `.example` hosts, with fragment-assembled canary keys. Nothing works against a real target or names
  a real person or organisation. One thing to know: the demo's `fetch_url` and `post_webhook` servers
  are real, generic tools that contact whatever URL they are given. The demo only gives them loopback
  URLs, and they are not exposed beyond the demo run.
- **`.claude/settings.json`:** deny rules for hook-skipping/force pushes only. Fine to publish.
- **Tarball:** 74 files (dist, LICENSE, NOTICE, README, package.json), no tests, no corpus, no local
  paths.

## Code paths NOT tested

1. The `demo-gif` workflow is tested only by its own run; the tape has no assertion beyond its `Wait`
   conditions.
2. Issue-template rendering and the private-advisory link only work once the repo is public, with
   private vulnerability reporting enabled. Not testable while private.
3. The README's quick start was run step by step on Windows only. `npm link` on macOS/Linux is not
   exercised (CI covers `npm pack` + global install instead).
4. The README's configuration example is not loaded by any test. Its keys were checked by hand against
   `src/config/schema.ts`.

## Release-day checklist (owner-confirmed steps marked ⚑)

1. ⚑ Owner files the SDK progress-race issue upstream; then re-add the drafts linking to it (R6.5-4).
2. Final `npm run check` and gitleaks full-history scan on the release commit.
3. ⚑ Push `main` and the `v0.1.0` tag; CI green.
4. ⚑ Make the repository public, and **in the same sitting** enable secret scanning, push protection,
   private vulnerability reporting, and branch protection on `main` requiring CI + gitleaks.
5. ⚑ Publish the GitHub release `v0.1.0` from the drafted notes, with `mcphantom-0.1.0.tgz` (packed
   from the tag) and its SHA-256 attached. **No npm publish** (waits for v1).
