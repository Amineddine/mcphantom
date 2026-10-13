# Contributing

Thanks for looking. MCPhantom is a security tool whose value rests on its claims being true, so the
ground rules are mostly about evidence.

## Before you start

- Security vulnerabilities go through [SECURITY.md](SECURITY.md), never a public issue.
- For anything larger than a fix, open an issue first. Scope and sequencing live in
  [docs/DESIGN.md](docs/DESIGN.md); changes to them are recorded in its change log.

## Development

Requires Node ≥ 22.13.

```sh
npm install        # also installs the pre-push hook (.githooks/pre-push runs `npm run check`)
npm run check      # lint, typecheck, build, tests — must pass before every push
npm run demo       # deterministic end-to-end demo
```

`npm test` alone skips typechecking; always run the full `npm run check`.

## Ground rules

1. **Fail closed.** An error, timeout or unexpected input in a gate ends in deny, never allow.
2. **No unmeasured claims.** A change that claims to detect or block something comes with a test that
   fails without it, and, for detection changes, an updated benchmark (`bench:scanner`,
   `bench:evasion`). Report misses; never relabel a case to make a number look better.
3. **Rerun the benchmarks after matcher/decoder changes:** `npm run bench:evasion` and
   `npm run bench:policy`. The policy deadline is fail-closed, so a slow predicate turns into false
   denies.
4. **Publish bypasses.** A known evasion is pinned as a test and listed in the benchmark results, not
   left out.
5. **Server-provided data is attacker-controlled** — descriptions, annotations, outputs. It may tighten
   a decision, never loosen one.
6. **Secret-shaped test fixtures** (fake AWS keys, tokens) are assembled at runtime from fragments, so
   secret scanners do not flag the repository. Use obviously fake values and `*.example` domains.
7. **List what you did not test** in the pull request description.

## Pull requests

Keep them focused, explain the threat or bug addressed, and include the test evidence (`npm run check`
output, benchmark diffs). CI runs on Linux, macOS and Windows × Node 22/24 plus a full-history gitleaks
scan. By contributing you agree your contribution is licensed under Apache-2.0.
