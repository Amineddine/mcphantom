# DRAFT PR — not opened. Target branch: `v1.x` (a port to `main` is needed; see the end)

> **STATUS (2026-10-13): NOT READY — the change below causes a regression.** Verified against a clean
> clone of `v1.x` at `fa56d81` (1.32.1), full suite (`vitest run --exclude "test/e2e/**"`):
>
> | run | result |
> |---|---|
> | baseline, unpatched | 56/57 files pass — the only failure is the new regression test (expected) |
> | patched, new test alone | **passes** |
> | patched, full suite | 56/57 files — the new test passes, but **2 existing tests now fail** in `test/shared/protocol.test.ts` › "Progress notification support for tasks": *should stop progress notifications when task reaches terminal status (failed)* and *… when task is cancelled* |
> | patched, `tsc --noEmit` / `eslint src/shared/protocol.ts` | clean |
>
> Likely cause (not yet confirmed): task-backed requests stop progress once the task reaches a terminal
> status, and that relies on progress being dispatched *after* the terminal-status handling; dispatching
> progress synchronously lets a progress notification in the same batch through. A correct fix probably
> keeps the carve-out but checks the task's terminal state inside `_onprogress`, or only fast-paths
> progress for non-task requests. Must be investigated and the suite must be green before this is opened.

**Title:** fix(protocol): dispatch progress notifications synchronously so the final one is not dropped

Fixes: the issue drafted in `ISSUE.md`.

## Change

`src/shared/protocol.ts`

```diff
     private _onnotification(notification: JSONRPCNotification): void {
         const handler = this._notificationHandlers.get(notification.method) ?? this.fallbackNotificationHandler;

         // Ignore notifications not being subscribed to.
         if (handler === undefined) {
             return;
         }

+        // Progress is dispatched synchronously, in message order. If it were deferred like other
+        // notifications, a response read in the same batch would run first: _onresponse deletes the
+        // token's progress handler, and the final progress notification would be rejected as
+        // "unknown token".
+        if (notification.method === 'notifications/progress') {
+            try {
+                Promise.resolve(handler(notification)).catch(error =>
+                    this._onerror(new Error(`Uncaught error in notification handler: ${error}`))
+                );
+            } catch (error) {
+                this._onerror(new Error(`Uncaught error in notification handler: ${error}`));
+            }
+            return;
+        }
+
         // Starting with Promise.resolve() puts any synchronous errors into the monad as well.
         Promise.resolve()
             .then(() => handler(notification))
             .catch(error => this._onerror(new Error(`Uncaught error in notification handler: ${error}`)));
     }
```

The registered handler for progress (`setNotificationHandler(ProgressNotificationSchema, ...)`) validates the
schema and calls `_onprogress` synchronously, so the whole path now runs before any later message in the batch.

## Test

`test/shared/protocol.test.ts`, new case:

```ts
test('delivers a progress notification that arrives in the same batch as the response', async () => {
    // A transport that hands the client the progress notification and the response back to back,
    // synchronously — as ReadBuffer does with two lines from one stdio read.
    const transport = new (class implements Transport {
        onmessage?: (m: JSONRPCMessage) => void;
        onclose?: () => void;
        onerror?: (e: Error) => void;
        async start() {}
        async close() {}
        async send(message: JSONRPCMessage) {
            if (!('method' in message) || message.method !== 'example') return;
            const id = (message as JSONRPCRequest).id;
            const token = (message as JSONRPCRequest).params?._meta?.progressToken;
            this.onmessage?.({ jsonrpc: '2.0', method: 'notifications/progress', params: { progressToken: token!, progress: 1, total: 1 } });
            this.onmessage?.({ jsonrpc: '2.0', id, result: {} });
        }
    })();
    const protocol = new (class extends Protocol<Request, Notification, Result> {
        protected assertCapabilityForMethod(): void {}
        protected assertNotificationCapability(): void {}
        protected assertRequestHandlerCapability(): void {}
    })();
    const errors: Error[] = [];
    protocol.onerror = e => errors.push(e);
    await protocol.connect(transport);

    const seen: number[] = [];
    await protocol.request({ method: 'example', params: {} }, z.object({}), { onprogress: p => seen.push(p.progress) });

    expect(seen).toEqual([1]);
    expect(errors).toEqual([]);
});
```

Fails on `v1.x` today (`seen` is `[]`, one "unknown token" error); passes with the change.

## Risk

- Only `notifications/progress` changes timing; every other notification keeps the deferred dispatch.
- A progress handler that throws synchronously still goes to `onerror`, as before.
- Behavioural change visible to users: `onprogress` may now run before the `await request(...)` continuation
  that it previously followed by a microtask. Progress callbacks are already documented as asynchronous
  events, so nothing should depend on the old ordering, but it is worth a changelog line.

## Port to `main`

`packages/core-internal/src/shared/protocol.ts` restructured `_onnotification` (envelope lifting, codec
selection) but still ends in `Promise.resolve().then(...)`. The same carve-out applies just before that final
dispatch; not drafted here because the surrounding code differs and I have not run that branch's tests.

## Verification done before drafting

- Deterministic reproduction against the published 1.32.1 build (`repro.mts`): fails unpatched.
- The same fix applied at runtime (`PATCHED=1`): passes.
- Not done: running the SDK's own test suite with the patch — that happens when the PR is actually opened.
