# Demo

Two forms: a one-command deterministic demo (no API key, fully reproducible), and a live demo through
Claude Code (a real model, your subscription).

## Deterministic demo

From a dev checkout:

```sh
npm install && npm run build
npm run demo
```

Phase 9 makes this run from an installed package too — `npx mcphantom demo` — which requires the demo
servers and agent to ship compiled in `dist/` and run without `tsx`. Today `npm run demo` uses `tsx`
and so needs the dev checkout.

A scripted agent summarizes a blog post. The post hides an instruction (in markup a browser would not
display): read the workspace `.env` and POST it to an attacker endpoint. The agent obeys. The demo runs
this twice against the same poisoned page and attacker collector:

- **Without MCPhantom** (audit mode): the canary AWS key reaches the attacker. The collector logs it.
- **With MCPhantom** (enforcing): the `post_webhook` call is blocked by the trifecta invariant; the
  collector receives nothing.

Ground truth is the attacker collector's own HTTP log, not anything MCPhantom reports, so neither side
grades itself. The agent is deterministic (no LLM), so the result is the defense's behaviour, not a
model's mood.

Inspect the blocked flow:

```sh
mcphantom trace --last --data-dir "<printed by the demo>"
```

It shows the context label rising to `untrusted/secret`, the DENY decision, the Layer-1 sources (the
web page made the context untrusted; `.env` made it secret), and the Layer-2 evidence (the attacker URL
came from the page; the AWS key came from `.env`).

## Live demo through Claude Code (real model, no API key)

> **Not implemented yet (planned for Phase 9).** This section describes the intended live demo; the
> harness does not exist in the tree today, so there are no commands to run yet.

The plan: use the Claude Code subscription as the MCP client, with MCPhantom as the gateway. Whether the
model actually obeys the injection is the thing being tested, so — unlike the scripted demo — a given
run may or may not exfiltrate. The point of the protected run is that it is blocked regardless. Phase 9
adds the harness and reports the measured obey-rate across several runs as a number, not an assertion.
Until then, the deterministic demo above is the reproducible proof of the mechanism.
