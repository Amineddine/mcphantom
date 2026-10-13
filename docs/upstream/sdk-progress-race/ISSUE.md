# DRAFT — not filed. Target: modelcontextprotocol/typescript-sdk

**Title:** Final progress notification dropped as "unknown token" when it arrives in the same read as the response

## Summary

`Protocol._onnotification` dispatches every notification one microtask late (`Promise.resolve().then(handler)`),
while `_onresponse` runs synchronously and deletes the request's progress handler. When a server's last
`notifications/progress` and the matching response are processed in the same synchronous batch — which happens
on stdio whenever both lines arrive in one read, since `ReadBuffer` dispatches them back to back — the response
handler runs first, the progress handler is gone by the time the deferred dispatch runs, and the notification
is rejected:

```
Received a progress notification for an unknown token: {"method":"notifications/progress","params":{"progress":1,"total":1,"progressToken":1}}
```

The client's `onprogress` never sees the final update, even though the server sent it before the response,
in order.

## Versions

- `@modelcontextprotocol/sdk` 1.32.1 (also present on `v1.x` at `src/shared/protocol.ts` and on `main` at
  `packages/core-internal/src/shared/protocol.ts`, which still defers via `Promise.resolve()`).
- Node 22 and 24; observed on Linux GitHub runners (stdio batches reads more often than on Windows).

## Reproduction (deterministic)

`repro.mts` (attached) uses a minimal transport that delivers the progress notification and the response
synchronously, back to back — exactly what `ReadBuffer` does with two lines from one stdio chunk.

```
$ npx tsx repro.mts
{"seen":[],"errors":["Received a progress notification for an unknown token: ..."]}
```

Expected: `{"seen":[1],"errors":[]}`.

In practice: a client calling a tool that reports progress up to 100% sees updates stop at the step before
the last one, nondeterministically. We hit it as a flaky CI test asserting `[1,2,3,4]` and receiving `[1,2,3]`
on Linux only.

## Cause

`src/shared/protocol.ts` (v1.x):

- `_onnotification` (≈ line 681): `Promise.resolve().then(() => handler(notification))` — deferred.
- The progress handler is registered as an ordinary notification handler (≈ line 371) and therefore inherits
  the deferral.
- `_onresponse` deletes `_progressHandlers` for the message id synchronously.

Ordering on the wire is preserved; it is the asymmetric dispatch (deferred notifications, synchronous
responses) that reorders them inside the client.

## Proposed fix

(The issue itself is ready to file: the bug is reproduced deterministically. The fix below is not — see
the status note in `PR.md`: the naive version breaks two task-progress tests.)

Dispatch `notifications/progress` synchronously, in message order, keeping the existing error handling. Other
notifications keep the current deferred behaviour, so the change is narrow. Draft PR attached (`PR.md`).
With the change applied (`PATCHED=1 npx tsx repro.mts`): `{"seen":[1],"errors":[]}`.

Alternative considered: defer the response the same way. Rejected — it changes the timing of every request,
not just progress.
