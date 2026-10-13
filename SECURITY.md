# Security policy

MCPhantom is a security tool, so a flaw in it can leave users exposed while they believe they are
protected. Reports are very welcome.

## Reporting a vulnerability

**Please report privately via GitHub's private vulnerability reporting:**
[Security → Report a vulnerability](https://github.com/Amineddine/mcphantom/security/advisories/new).
This is the only reporting channel; please do not open a public issue, pull request or discussion for
an unpublished vulnerability.

Please include the MCPhantom version or commit, OS and Node version, the config/policy involved, and a
minimal reproduction (ideally a failing test or a small MCP server). Use synthetic secrets only.

## What counts

In scope: a way past a protection MCPhantom claims to provide, or a way to make it harm the user it
protects. For example:

- an egress/exec call allowed while the session holds untrusted and secret data, without a declassify
  entry that permits it;
- a poisoned or changed (unpinned) definition reaching the model through `tools/list`, `prompts/list`
  or server `instructions`, when the scanner or the lockfile claims to cover that case;
- a fail-open: an error, timeout or malformed input that ends in *allow* instead of deny;
- secrets written unredacted to the event log under `logging.payloads: redacted`;
- MCPhantom widening what a server can see or do compared with connecting it directly (environment,
  files, sampling);
- weaknesses in MCPhantom's own files (permissions, lockfile signature) beyond the scope stated in
  [docs/DESIGN.md](docs/DESIGN.md) §1.

Not new vulnerabilities (a public issue is fine): anything already listed under
["Known limitations and bypasses"](README.md#known-limitations-and-bypasses) or in
[bench/results/evasion-bench.md](bench/results/evasion-bench.md) — client-native tools, same-user
tampering, host actions by server processes, the published encoding/scanner bypasses. A *new* bypass
of the same kind (an encoding or disguise the design claims to handle) is in scope.

## What to expect

MCPhantom is maintained by one person on a best-effort basis. The target is to acknowledge a report
within 7 days and to agree a disclosure date with you; the default is 90 days, or earlier once a fix is
released. Fixed issues are credited in the advisory and the changelog unless you prefer otherwise.

## Supported versions

Only the latest release receives security fixes during 0.x.
