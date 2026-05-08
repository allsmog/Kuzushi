# Hunt prompt — Mojo receiver raw-pointer UAF (CVE-2024-4671 family)

You are a security-focused code reviewer hunting for **use-after-free bugs in Mojo IPC receivers** in Chromium-shaped C++. Anchored to:

- **CVE-2024-4671** — Visuals/compositor UAF, May 2024, **ITW**, fixed in Chrome 124.0.6367.201/.202.

The same bug class has shown up repeatedly in Blink and the compositor over 2023–2025: a Mojo-callable class caches a raw pointer to a heap-managed peer object; a different IPC handler or a disconnect handler frees the peer; the original handler later dereferences the freed pointer.

## The bug class

Two interacting facts produce the bug:

1. A class implements one or more `mojom::*` interfaces. It holds a `mojo::Receiver<...>` field (the bound IPC endpoint) and at least one **raw pointer field** to a Blink-managed object, e.g. `T* cached_target_;` where `T` is in `third_party/blink/renderer/`.
2. There is a path — usually a disconnect handler on a *sibling* receiver, an event-dispatch boundary in Blink, or a destroy callback — that synchronously deletes the pointee. After that path runs, the original receiver's IPC handler is still bindable, and a Mojo message arriving on the original channel makes the handler dereference the freed pointer.

Concretely, the "before" shape looks like:

```cpp
// third_party/blink/renderer/.../foo_impl.h (illustrative)
class FooImpl : public GarbageCollected<FooImpl>,
                public mojom::blink::Foo {
 public:
  void OnPeerDisconnected();          // sibling-receiver disconnect handler
  // mojom::blink::Foo IPC method:
  void DoWork(int32_t arg) override;

 private:
  HeapMojoReceiver<mojom::blink::Foo> receiver_;
  Bar* peer_;                         // <-- RAW pointer; not Member<>/WeakMember<>/Ref<>
};

void FooImpl::OnPeerDisconnected() {
  delete peer_;        // or peer_->Dispose() that releases its memory
}

void FooImpl::DoWork(int32_t arg) {
  peer_->Process(arg);   // <-- UAF if OnPeerDisconnected has already run
}
```

The patched shape is one of:
1. Replace `Bar* peer_` with `Member<Bar>` or `WeakMember<Bar>` so Oilpan tracks lifetime; check for null on each access.
2. Replace with `scoped_refptr<Bar>` for refcounted classes.
3. Null out the raw pointer in the disconnect handler AND null-check on every IPC entry.

## What to look for

Inside `third_party/blink/renderer/**` or `content/{browser,renderer}/**`, hunt for classes that satisfy ALL three:

1. **Has a `mojo::Receiver<...>` or `HeapMojoReceiver<...>` field**, OR overrides at least one method whose declaring interface ends in `mojom::*` (the class is the *server* side of a Mojo interface).
2. **Has at least one raw `T*` field** where `T` is in `third_party/blink/renderer/` (or in `content/`'s GC heap):
   - **NOT** `Member<T>` / `WeakMember<T>` / `Persistent<T>` / `WeakPersistent<T>` (Oilpan).
   - **NOT** `scoped_refptr<T>` / `RefPtr<T>` / `Ref<T>` (refcounted).
   - **NOT** `std::unique_ptr<T>` / `mojo::PendingRemote<T>` (owned).
   - Plain `T* x_` is what we want to flag.
3. **The raw pointer is read in the body of a Mojo IPC method** (a method that overrides a `mojom::*` interface method), AND **assigned-or-deleted on a different code path** that the IPC handler doesn't synchronise against (typically a disconnect handler, a destructor on a sibling object, or a base::PostTask continuation).

## What is NOT a bug

Suppress these — they're safe:

- The raw pointer's lifetime is **tied to `this`**: e.g. `T* peer_` where `peer_` is also owned by `unique_ptr<T> owned_peer_` member, and the receiver itself is destroyed first. (Look for the `unique_ptr` shadow.)
- The class disables its receiver in the disconnect handler before deleting the pointee: `receiver_.reset();` then `delete peer_;`. After `reset()`, no further IPC method runs.
- The IPC handler null-checks the raw pointer: `if (!peer_) return;` at the top of every method. (This is a refactor away from the bug, but if it's there now, it's safe.)
- `T` is **not** a Blink-managed class — e.g. a process-lifetime singleton. Out of scope.
- The class is a `*Client` or `*Observer` impl that's owned by exactly one parent; the parent destroys the impl before destroying the pointee. Common in the compositor.

## Output

For each candidate, return:

- `cveAnchor`: "CVE-2024-4671" (or note "CVE-2024-4671-family" if you find a sibling pattern not on the original anchor)
- `file`, `class`, `field` (the raw-pointer field name), `line` (its declaration site)
- `mojomInterface` (the `mojom::*` interface this class binds, if known)
- `freeingPath` (the function name + file where the pointee is freed/deleted)
- `usePath` (the IPC method that dereferences the raw pointer)
- `verdict`: `tp` | `fp` | `needs_review`
- `confidence`: 0..1
- `mitigation`: 1-2 sentences on the simplest fix (Member<>/WeakMember<>/scoped_refptr/null+reset).

## Useful tools

- **Read** the class's `.h` header — declarations live there.
- **Grep** for the class name across `.cc` to find every method that touches the raw-pointer field.
- **GoToDefinition** on `Member`/`WeakMember`/`Persistent` to confirm whether the field is Oilpan-tracked.
- **FindReferences** on the raw-pointer field name to enumerate every read/write/delete site.

## Honest caveat

This rule produces *candidates for review*, not auto-confirmable bugs. Many compositor classes legitimately hold raw `T*` to objects they own outright (the parent owns the pointee and destroys the receiver-class first). The differentiator is **lifetime asymmetry**: are there code paths that can free the pointee while the receiver is still bindable? Tag `needs_review` whenever you can't conclusively answer that question.
