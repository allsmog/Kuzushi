# pwn-threadweaver — example reference exploit

A reference exploit demonstrating Kuzushi's pwn module against a real heap
UAF challenge (HackTheBox `pwn_threadweaver`). The binary is a multi-threaded
task processing server with a refcount-based free path that fails to clear
the slot's `alive` flag and data pointer, leaving every freed chunk usable
through View / Edit / Process operations.

## The vulnerability

`Delete` decrements the per-slot refcount atomically and calls `free()` once
it hits zero, but it does NOT reset `alive` to 0 or zero out `data`. With
`alive` still set, the slot looks valid to every other menu action, so the
binary happily reads/writes/processes the freed chunk — a classic dangling
pointer UAF.

The `pwn:heap-uaf-scan` tool surfaces this pattern directly:

```bash
kuzushi run pwn:heap-uaf-scan --input '{"binary":"./threadweaver"}'
```

Output excerpt:

```json
{
  "summary": {
    "atomicDecrementSites": 2,
    "freeCallSites": 2,
    "likelyRefcountPattern": true,
    "likelyUafPattern": true,
    "likelyThreaded": true,
    "usesPthreads": true
  },
  "exploitationHints": [
    "Refcount-based free without pointer/alive clear is the canonical UAF pattern -- delete leaves slot reusable for View/Edit primitives.",
    "Standard tcache poisoning workflow: free two chunks of the same size, leak fd via UAF view, edit fd to redirect malloc to a controlled address."
  ]
}
```

## Probing the menu

`pwn:menu-probe` interacts with the binary and pulls out the menu options
without you having to type them by hand:

```bash
kuzushi run pwn:menu-probe --input '{
  "binary": "./threadweaver",
  "env": {"LD_LIBRARY_PATH": "."},
  "maxChoices": 8
}'
```

It captures `1. Create task`, `2. Edit task`, ..., `8. Exit` and reports
which choices trip the "[-] Invalid choice" branch versus producing a real
prompt.

## Running the exploit

`exploit.py` chains:

1. UAF View of two freed tcache entries to recover heap base via the
   safe-linking PROTECT/REVEAL relation.
2. Tcache poison via UAF Edit of the head's fd pointer, redirecting the
   second `malloc` into the body of a 0x4f0 chunk that glibc allocated
   during `dlopen()` of `libplugin.so`.
3. Delete that aliased slot — the chunk goes to the unsorted bin (too big
   for tcache), and the chunk's `fd` lands at `heap+0x2c0`, holding the
   `&main_arena.bins[0] - 0x10` sentinel. View the slot to leak libc.

The `pwn:exploit-run` tool drives the script under a wall-clock timeout
and pulls the leak markers + flag pattern out of stdout/stderr:

```bash
kuzushi run pwn:exploit-run --input '{
  "script": "./exploit.py",
  "timeoutMs": 15000
}'
```

Sample output:

```json
{
  "exitStatus": "exit status: 0",
  "leaks": [
    {"line": "[+] heap_base = 0x555556376000", "value": "0x555556376000"},
    {"line": "[+] libc base = 0x7ff1c2000000", "value": "0x7ff1c2000000"}
  ]
}
```

## Files

- `exploit.py` — the pwntools script. Expects `threadweaver`, `libc.so.6`,
  and `ld-linux-x86-64.so.2` in the working directory; download the
  challenge archive separately.

## What's NOT here

Full RCE. The exploit stops once it has heap + libc leaks. Going from
there to a shell on glibc 2.39 with Full RELRO + IBT + SHSTK enabled
typically needs an FSOP attack on `_IO_2_1_stdout_` plus a way to land
the FSOP write without immediately crashing the next `printf` — the
binary's 5-slot create limit and Create's mandatory 256-byte memset of
freshly-allocated chunks make that surprisingly fiddly. Treat the example
as a primitives demonstration and a Kuzushi tool showcase rather than a
complete weaponised exploit.

## exploit_fsop.py — work-in-progress FSOP variant

`exploit_fsop.py` is a separate, longer chain that demonstrates the
stdout-buffer-hijack technique the user suggested. It:

1. Gets the heap leak via UAF (same as `exploit.py`).
2. Forces a libc leak via the **smallbin / worker-tcache overflow**
   trick instead of the dl-chunk free path. We Edit slot 0 to clear
   A's tcache key, then Process slot 0 eight times. The worker thread
   has its own per-thread tcache (separate from main's), so after seven
   `tcache_put`s its tcache fills, and the eighth `_int_free(A)` skips
   tcache and routes A into the unsorted bin. A's fd field now holds
   `&main_arena.bins[0] - 0x10`, giving libc base.
   This route is important because it doesn't burn slot 4 — we still
   have a Create budget left for the FSOP stage.
3. Tcache-poisons via slot-3 alias to `tcache_perthread_struct`, then
   lands slot 4 at `_IO_2_1_stdout_ - 0x90`. Create's 256-byte memset
   zeroes bytes 0..0x6f of the stdout struct (`_flags`, all the
   `_IO_*_ptr`/`_*_base`/`_*_end` fields) but PRESERVES `_fileno` at
   offset 0x70 (still `=1`) and the vtable at offset 0xd8 (still
   `=_IO_file_jumps`). The followup printf `[+] Task 4 created…` is
   what verifies the corruption survives — that line reliably appears
   on stdout.
4. Edits slot 4 with a fake stdout body: `_flags = 0xfbad0800` (with
   `_IO_CURRENTLY_PUTTING` set, so `_IO_new_file_overflow`'s prelude
   doesn't reset the buffer pointers), and `_IO_write_base`/
   `_IO_buf_base` aimed at `heap_base + 0x2d0`. That heap address is
   inside the still-intact dl-runtime chunk so it should hold
   libplugin/ld/binary pointers (= a PIE leak the moment we trigger a
   flush).

What goes wrong: the next time anything frees a chunk through the
non-tcache path (notably the worker's `tcache_thread_shutdown` when
the binary exits via option 8) it sees that the iter-8 free in step 2
already cleared B's `prev_inuse` bit, and aborts with `double free or
corruption (!prev)` before the flush we'd be reading actually reaches
us. The libplugin pointers never get dumped.

The FSOP setup itself is sound — it survives the menu's followup
printfs and the binary stays alive after the Create corruption — but
the worker-tcache overflow path leaves an `_int_free`-side
consistency check unsatisfiable later, and we run out of slots before
we can clean it up. Open questions if anyone picks this up:

- Replace the smallbin trick with a different libc-leak primitive that
  doesn't leave A in a half-freed state (a write-to-unsorted via
  tcache-perthread direct manipulation might work).
- Or build the FSOP via stderr-hijack so the dump fires during an
  earlier printf, before the worker's exit.
- Or just keep the multi-slot budget tighter and reserve one Create
  for an actual `open(/flag.txt)` setcontext-chain trigger.
