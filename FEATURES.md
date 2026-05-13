# Kuzushi Feature Notes

## Pwn And rev.ng Readiness

Kuzushi already has the start of a useful binary-exploitation workflow in source:

- `pwn:profile-binary`
- `pwn:reverse`
- `pwn:state`
- `pwn:calibrate-local`
- `pwn:run-candidates`
- `pwn:auto-solve`

The source tree also includes a rev.ng-backed MCP server under
`crates/kuzushi-mcp-revng`, and `pwn:reverse` is designed to use rev.ng for
reverse-engineering observations.

During the HTB scanner challenge, that integration was not operational in the
current environment:

- The built `target/debug/kuzushi` binary did not expose `revng` as an MCP
  health backend.
- Native `revng` was not available on `PATH`.
- Docker and Podman were not installed, so the `revng/revng:latest` fallback
  could not run.
- `target/debug/kuzushi-mcp-revng` was not built.
- The repository was left in a conflicted state after `git pull --autostash`,
  so rebuilding or validating the latest source was not safe without resolving
  the pull conflicts first.

## What Would Have Helped

For binary exploitation challenges, Kuzushi should make the pwn path
operational and reproducible before leaning on generic security scanning.
The most useful improvements are:

1. Make `pwn:profile-binary` and `pwn:reverse` available in the normal built
   CLI and shell surfaces.
2. Make `kuzushi mcp health revng` work consistently for native rev.ng and
   Docker/Podman-backed rev.ng.
3. Add a one-command pwn preflight that checks `revng`, container runtime,
   paired libc/ld, `checksec`-style properties, symbols, strings, and CET flags.
4. Have `pwn:reverse` produce structured function facts: dangerous IO,
   allocation/free sites, function-pointer tables, bounded/unbounded loops,
   stack locals, and attacker-controlled lengths.
5. Add exploit-harness generation for local/remote menu binaries, including
   transcript capture, retry logic, leak helpers, and local/remote switches.
6. Add oracle discovery for OOB read patterns, especially scanner loops that
   compare attacker-controlled pattern lengths against fixed-size buffers.
7. Add glibc heap helpers for tcache bin modeling, fake chunk validation,
   poisoning plans, hook targets, and RELRO constraints.
8. Add crash-debug integration around `strace` and optional GDB: collect
   signals, crash addresses, maps, and classify addresses as PIE/libc/heap/stack.
9. Persist pwn state under `.kuzushi/runs/<id>/`, including leaks, bases,
   failed strategies, crash logs, generated exploit scripts, and remote
   transcripts.
10. Add libc fingerprinting from leaks: normalize leaked return addresses
    against candidate glibc builds, cache matching libc/ld packages, and
    report exact offsets for functions and gadgets.
11. Add constrained-write planning for byte-limited primitives: model target
    windows, bad bytes, low-byte ASLR constraints, reconnect predicates, and
    payload ordering.
12. Add staged ROP generation: stack alignment, pivot gadgets, `gets`/`read`
    second stages, newline checks, and reusable chains for `system`, `puts`,
    and memory disclosure.
13. Add memory-origin analysis for secrets: track startup reads, heap-resident
    buffers, retained pointers, `/proc/$PPID/maps` probes, and likely offsets
    for in-memory flags or tokens.

## Target Workflow

A useful workflow for a challenge like the HTB scanner binary would be:

```text
kuzushi run pwn:profile-binary '{"binary":"./scanner","libc":"./libc.so.6","ld":"./ld-2.31.so"}'
kuzushi run pwn:reverse '{"binary":"./scanner","backend":"revng"}'
kuzushi run pwn:calibrate-local '{"binary":"./scanner","argv":[]}'
kuzushi run pwn:state '{"binary":"./scanner","action":"merge","state":{...}}'
kuzushi run pwn:run-candidates '{"target":"154.57.164.67:31029","stateId":"..."}'
```

For the scanner challenge specifically, this should have surfaced:

- OOB read in the naive scanners caused by checking a fixed 4096-byte scan
  window while comparing an attacker-controlled pattern length.
- Off-by-one NUL write from the 16-byte scanner name read.
- PIE, libc, and stack leak opportunity from the OOB read oracle.
- CET/SHSTK making direct ROP unreliable.
- RELRO blocking writes to the scanner table.
- A viable non-ROP route through fake stack chunks, tcache poisoning, and
  `__free_hook = system`.

For the memento challenge specifically, this should have surfaced:

- Signed-length bug in `remember`: values like `0xff` pass the `len > 0x18`
  guard and drive a much longer write loop.
- Off-by-one/count corruption at `count == 0x18`, enabling stack disclosure
  through `recall` and constrained stack writes through the stored pointer.
- Remote libc identity from leaked `__libc_start_main` return sites; the useful
  remote match was Ubuntu glibc `2.39-0ubuntu8.7`, where small patch-level
  offset drift changed `system` and ROP gadget addresses.
- One-byte stack-pointer targeting constraints: only some ASLR low bytes let
  the primitive write the desired return slots, so the harness needed automatic
  reconnect/retry logic.
- Initial `system("cat flag.txt")` was the wrong objective: the flag was read
  into a heap allocation during startup and was not present as a file in the
  service working directory.
- A viable two-stage chain: `system("cat /proc/$PPID/maps")` to recover the
  heap base, then `gets` plus a stack pivot to load a second-stage ROP chain
  that calls `puts(heap + 0x2a0)`.

## Priority

The highest-impact work is not more generic scanning. The priority should be
making the existing pwn/rev.ng surface reliable, then adding exploit-development
machinery around it:

```text
pwn:preflight
pwn:reverse
pwn:harness
pwn:oracle
pwn:heap-glibc
pwn:debug-crash
pwn:libc-fingerprint
pwn:write-planner
pwn:rop-stage
pwn:memory-origin
```
