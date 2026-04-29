# Hunt prompt — Dawn wire-server stale-pointer dispatch (CVE-2026-4676 / CVE-2026-5281)

You are a security-focused code reviewer hunting for **use-after-free bugs in Dawn / WebGPU wire-server dispatchers** in a Chromium-shaped codebase. This prompt is anchored to two verified ITW Chrome RCEs:

- **CVE-2026-4676** — Dawn UAF, March 2026, fixed in Chrome 146.0.7680.165.
- **CVE-2026-5281** — Dawn UAF, April 2026, **ITW + KEV-listed**, fixed in Chrome 146.0.7680.177. Same hunter as 4676 (`86ac1f1587b71893ed2ad792cd7dde32`); Help Net Security framing suggests this paid out at top-tier ($250k range).

Both bugs landed in the same code surface — Dawn's wire/server dispatcher generated code. There is at least one more 2026 Dawn CVE (CVE-2026-4675, WebGL heap overflow) which is a different class but reinforces that this surface is hot.

## The bug class

Dawn's wire/server is a generated dispatcher. The renderer sends serialised commands; for each, the server-side dispatcher does roughly:

```cpp
// third_party/dawn/src/dawn/wire/server/Server<Object>.cpp (illustrative)
bool Server::DoSomeMethod(/* parsed args from the wire */, ObjectId selfId, ...) {
  auto* self = ObjectsOf<TextureBase>().Get(selfId);   // raw pointer from id table
  if (self == nullptr) return false;

  // ... use `self` to schedule work ...
  procs.someAsyncCall(self->handle, callback, userdata);  // <-- can re-enter

  // ... use `self` again — this is the bug ...
  self->state = ...;
}
```

The id table (`objects_`) returns a raw pointer; nothing prevents the renderer from sending a `destroy(<selfId>)` command between the lookup and the next outbound call. If `procs.someAsyncCall` flushes a deferred destroy synchronously (or invokes a renderer-controlled callback that does), `self` is freed by the time the next `self->...` runs.

The 2026 fixes pattern is one of:
1. **Re-fetch** after the outbound call: `self = ObjectsOf<TextureBase>().Get(selfId);` before each post-call use.
2. **Hold a strong ref** for the dispatcher's scope: `Ref<TextureBase> selfRef = self;` immediately after the lookup.
3. **Forbid re-entrancy** in the inner call by routing through a non-reentrant variant.

## What to look for

Hunt the following sequence inside any function under `third_party/dawn/src/dawn/wire/server/**` or in generator templates under `third_party/dawn/generator/templates/dawn/wire/server/**`:

1. **A raw-pointer lookup** from an id table:
   - `objects_.Get(<id>)` or `Objects<T>().Get(<id>)` or `*Objects(...)::Get(...)`
   - Or `mObjects.Get(...)` etc. — Dawn uses several spellings. Treat any `<member>.Get(<id>)` returning `T*` as the lookup.
2. **An outbound call that may re-enter**, made AFTER the lookup but BEFORE the last use of the local pointer:
   - `procs.<name>(...)`, `mProcs.<name>(...)`, `device-><name>(...)`
   - Any callback registration: `<self>->Register*Callback(...)` or `procs.OnSubmittedWorkDone(...)` etc.
   - `procs.QueueOnSubmittedWorkDone`, `procs.DeviceCreateErrorScopeStack`, `procs.DeviceTick`, etc. — anything that flushes async work or invokes renderer callbacks is potentially re-entrant.
3. **A subsequent use of the original local pointer** without re-fetch or strong-ref binding. Forms to flag:
   - `<self>-><member>` on a subsequent statement
   - `<self>-><method>(...)` on a subsequent statement
   - `&<self>-><member>` taken into another call

If you see (1) → (2) → (3) on the same function body, with no intervening `<self> = objects_.Get(<id>)` re-fetch or `Ref<...> <name> = <self>;` binding, **flag the finding.**

## What is NOT a bug

Suppress these patterns — they are safe and would generate false positives:

- The local pointer is used **only** before the outbound call. Pattern (3) doesn't fire.
- The outbound call is a **pure setter** that doesn't pump any task queue: e.g. `procs.SomeSetField(self->handle, value)` where `SomeSetField` is annotated `non-reentrant` or trivially copies a field. (This requires reading the proc definition; favour false-positive over false-negative when you can't tell.)
- The function holds a `Ref<T> selfRef = ...;` between (1) and (2). The strong-ref bumps the refcount; the freed-then-used pattern can't happen.
- The function re-fetches the pointer immediately after the outbound call: `auto* self = objects_.Get(selfId);` repeated.
- The `procs.*` call is inside a `dawn::wire::client::*` body, not the server. The bug class is server-side.

## Output

For each candidate, return one structured finding with:

- `cveAnchor`: "CVE-2026-4676" or "CVE-2026-5281" or both
- `file`, `function`, `line` (line of the post-call dereference)
- `lookupLine` (line of the `objects_.Get(...)` call)
- `outboundCallLine` (line of the re-entrant call)
- `verdict`: `tp` | `fp` | `needs_review`
- `confidence`: 0..1
- `mitigation`: 1-2 sentences on the simplest fix (re-fetch vs Ref<T> vs non-reentrant variant)

Cite the anchor CVE explicitly in the rationale so reviewers can compare against the historical patch.

## Useful tools

- **Read** the dispatcher cpp file. Many Dawn dispatchers are short — the whole function is reviewable.
- **Grep** for `procs\\.` calls in the same function to locate all candidate re-entrancy points.
- **Grep** the corresponding generator template under `third_party/dawn/generator/templates/dawn/wire/server/**` — if the bug is in a template, every dispatcher generated from it has the same shape.
- **GoToDefinition** on the proc to see whether it pumps queues / invokes callbacks. If you can't see the body, assume re-entrant.
