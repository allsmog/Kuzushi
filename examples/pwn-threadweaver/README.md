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
