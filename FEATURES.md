# Kuzushi Feature Backlog

This file is roadmap/backlog material. It is not the current product surface.
The shipping product focus is the evidence-backed repository security
workbench described in `README.md`: doctor, context, scan, findings, proof,
suppression/verification/patching, and PR-ready reporting.

Features listed here should graduate only when they produce first-class
Kuzushi artifacts and fit the repository evidence loop. Experimental pwn,
rev.ng, pentest, governance, or defensive operations ideas must not displace
the primary golden path in user-facing docs or shell hierarchy.

## Pwn And rev.ng Readiness

Kuzushi has an experimental binary-exploitation workflow in source:

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
14. Add `pwn:protocol` to learn menu state machines and IO quirks: prompts
    without newlines, misleading labels, `scanf` mixed with raw `read`, and
    cases where menu choices and payload bytes must be sent separately.
15. Add `pwn:primitive-discovery` to translate reverse-engineering facts into
    concrete exploit capabilities: partial pointer writes, low-byte zeroing,
    arbitrary read/write/free candidates, global-array overlap, and BSS fake
    chunk opportunities.
16. Add `pwn:leak-decoder` for formatted leak channels. It should recover raw
    memory when bytes are wrapped in row prefixes, suffixes, padding, banners,
    or menu text.
17. Add `pwn:glibc-version-plan` so exploit planning is driven by the supplied
    libc. For glibc 2.37, hook overwrite plans such as `__free_hook = system`
    should be treated as stale; prefer safe-linking-aware tcache poisoning,
    stack return overwrite, FSOP, or other modern targets.
18. Add `pwn:stack-target` to use `environ` leaks plus stack scans to locate
    markers, saved frame pointers, active return slots, and reliable overwrite
    addresses.
19. Add `pwn:heap-layout-calibrate` to repeatedly run with the bundled
    `ld`/`libc`, infer chunk offsets, tcache keys, unsorted-bin offsets, and
    safe-linking formulas before attacking the remote service.
20. Add `pwn:exploit-skeleton` to generate robust local/remote exploit
    harnesses with transcript capture, leak parsers, retries, flushed progress
    logs, and post-shell command execution.
21. Add `pwn:hardening-map` to identify compiler/runtime protections beyond
    checksec: Clang SafeStack, custom shadow stacks, software CFI dispatch,
    hardware CET, stack canary storage, TLS-relative state, and which
    protections are policy checks versus writable process memory.
22. Add `pwn:tls-state-model` to map `fs:`/`gs:` slots, SafeStack pointers,
    canaries, locale/runtime pointers, and other thread-local state that an
    overflow may corrupt. It should distinguish exploitable corruption from
    crash-only corruption and suggest self-repair payloads.
23. Add `pwn:cfi-bypass-planner` to reason about indirect-call target
    validation, saved-register dependencies, CFI base registers, function-table
    ranges, PLT targets, and ways to make a legitimate call target invoke a
    useful primitive.
24. Add `pwn:micro-write-stage` for tiny write primitives such as 16- to
    64-byte `read`/`gets` windows. It should plan repeated stages, preserve
    required stack/TLS state, and synthesize chains that bootstrap from a small
    write into a full ROP or data-only exploit.
25. Add `pwn:side-effect-debugger` to classify why promising payloads die:
    stack-smash aborts, bad TLS locale pointers, CFI rejection, corrupted
    SafeStack metadata, misaligned stacks, blocked syscalls, and EOF/protocol
    desynchronization.
26. Add `pwn:cross-stack-layout` to model unsafe stack, safe stack, regular
    stack, custom shadow stack, and TLS as related regions. The planner should
    derive stable offsets from leaks and show which return slots, canaries, and
    saved registers can be reached by each primitive.
27. Add `pwn:remote-libc-resolver` that combines Dockerfile/package metadata,
    leaked symbol lows, known distro builds, local candidate packages, and
    online/offline libc databases to select exact libc/ld offsets before the
    final remote exploit.
28. Add `pwn:exit-handler-planner` for modern glibc targets where hook symbols
    such as `__free_hook` still exist but are no longer invoked. It should model
    `__exit_funcs`, `ef_cxa` records, pointer-mangled handlers, `_dl_fini`, and
    `system(command)` exit-handler hijacks.
29. Expand `pwn:tls-state-model` to explicitly include `fs:0x30` /
    `pointer_guard`, including ways to recover it from existing mangled glibc
    handlers or overwrite it when an arbitrary-write primitive reaches TLS.
30. Expand `pwn:heap-layout-calibrate` to track tcache bin counts, not just
    safe-linking keys and chunk offsets. The planner should know when a poisoned
    allocation requires a two-entry bin rather than a single freed chunk.
31. Add `pwn:malloc-side-effect-planner` to warn when unsorted-bin corruption or
    fake chunk metadata makes later `malloc` calls unsafe, and suggest exploit
    triggers that avoid fresh allocations after heap metadata abuse.
32. Add `pwn:remote-command-capture` for services where
    `system("/bin/sh")` is unreliable under `socat EXEC` or other one-shot
    transports. It should prefer command strings placed in writable memory, such
    as `system("cat flag.txt; id")`, when the goal is output capture rather than
    an interactive shell.
33. Add `pwn:sandbox-helper-protocol` for multi-process sandboxes that use
    shared memory, pipe fd tables, helper children, and uneven seccomp policy.
    It should recover helper protocols, model which mappings are shared after
    `fork`, and identify when an attacker-controlled VM can reroute requests
    directly to a less-restricted helper.
34. Add `pwn:path-sanitizer-boundary` to detect fixed-window sanitizers that
    clean only one buffer slot while later C-string consumers continue into
    adjacent attacker-controlled memory. It should model missing NUL
    terminators, max-length path components, and path-resolution tricks such as
    `long-directory/../../target` where traversal bytes live outside the
    sanitized window.
35. Add `pwn:trusted-helper-rewrite` to notice allowlisted helper binaries that
    are writable by the service user. When direct command arguments are blocked,
    the planner should try replacing the exact allowed executable with a small
    script or payload and then invoke the original allowlisted command path.

## Target Workflow

A useful workflow for a challenge like the HTB scanner binary would be:

```text
kuzushi --target . run pwn:profile-binary --input '{"binary":"./scanner","libc":"./libc.so.6","ld":"./ld-2.31.so"}'
kuzushi --target . run pwn:reverse --input '{"binary":"./scanner","backend":"revng"}'
kuzushi --target . run pwn:calibrate-local --input '{"binary":"./scanner","argv":[]}'
kuzushi --target . run pwn:state --input '{"binary":"./scanner","action":"merge","state":"<state-json>"}'
kuzushi --target . run pwn:run-candidates --input '{"target":"154.57.164.67:31029","stateId":"<state-id>"}'
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

For the Magic Scrolls challenge specifically, this should have surfaced:

- Misleading menu dispatch and IO synchronization hazards: the displayed
  `1..6` labels did not match the raw `0..5` exit behavior, one prompt had no
  newline, and `scanf` plus raw `read` required payloads to be sent after the
  `Spell:` prompt rather than buffered with the menu choice.
- `power=4` turned magic-number updates into writes over `spells[0]` and
  `spells[1]`, giving partial low-byte zeroing, arbitrary pointer selection,
  arbitrary read through the favorite-spell printer, and arbitrary free.
- The favorite-spell leak channel was formatted with banners, row prefixes,
  suffixes, and padding, so raw memory needed a decoder before heap/libc/stack
  values were trustworthy.
- Local heap calibration exposed the tcache safe-linking key, deterministic
  chunk offsets, and the unsorted-bin libc pointer offset before the remote run.
- glibc 2.37 made hook-overwrite plans stale; the useful route was a fake BSS
  chunk, safe-linking-aware tcache poisoning, `environ` stack discovery, and a
  stack return overwrite with `system("/bin/sh")`.

For the CFI/SafeStack challenge specifically, this should have surfaced:

- The binary was not just PIE/NX/RELRO/canary protected; it also combined
  Clang SafeStack, a writable custom shadow-stack check, and software CFI over
  an indirect call site. A `pwn:hardening-map` pass should have reported the
  exact protection model and which state lived in writable TLS or stack memory.
- The large `gets` overflow reached the unsafe stack pointer and master canary
  in TLS, which made naive payloads crash later in libc/runtime code. A
  `pwn:tls-state-model` should have identified `__safestack_unsafe_stack_ptr`,
  the stack canary slot, and fragile TLS-adjacent runtime pointers that needed
  preservation or repair.
- The useful primitive was not a single overwrite. It was a staged exploit:
  leak SafeStack and PIE, pivot a tiny raw `read` window, repair enough TLS
  state for the process to survive, satisfy the CFI target check, then extend
  into a GOT leak and ret2libc chain.
- `pwn:cfi-bypass-planner` should have connected the CFI register/base
  dependency to a legitimate PLT target, then proposed making the validated
  indirect call reach `read@plt` as a write primitive.
- `pwn:micro-write-stage` should have generated the repeated 40-byte write
  stages needed to build a larger ROP chain, leak `read@GOT`, resolve libc,
  and call `system("/bin/sh")`.
- `pwn:side-effect-debugger` should have explained the common failed attempts:
  stack canary aborts, CFI rejection, corrupted SafeStack metadata, bad
  TLS/runtime pointers reached by `strtol`, and IO desynchronization.
- `pwn:remote-libc-resolver` should have matched the leaked `read` address to
  the remote Ubuntu glibc 2.35 build and emitted verified offsets for `read`,
  `system`, and `/bin/sh`.

For the Sandcastle challenge specifically, this should have surfaced:

- The VM, parent coordinator, filesystem helper, and exec helper communicated
  through a shared fd table and shared memory slots. A helper-protocol pass
  should have recovered the pipe directions, request structs, output slots, and
  which child had weaker policy.
- `scanf("%ud")` followed by raw `read` meant the size line and bytecode had to
  be sent separately; sending both in one buffered write desynchronized the
  program load.
- The VM could write beyond its private stack into the shared fd table, which
  allowed direct requests to the exec helper by changing the VM request fd from
  the parent pipe to the exec request pipe and the response fd to the exec
  response pipe.
- The remote service accepted exact `date` execution but rejected shell
  metacharacters and arguments, so the exploit needed a path that still invoked
  the exact allowlisted command.
- The filesystem sanitizer only rewrote the first 255-byte path slot. A
  255-byte directory name with no NUL let `open` continue into the next shared
  slot, where `/../../date` was unsanitized. Creating that directory and
  preloading the adjacent slot made a sanitized write resolve to
  `/home/ctf/date`.
- Because `/home/ctf/date` was writable by the `ctf` user and executable mode
  was preserved on truncate, overwriting it with a short shell script let exact
  `date` execution print the flag without needing an interactive shell.

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
pwn:protocol
pwn:primitive-discovery
pwn:leak-decoder
pwn:glibc-version-plan
pwn:stack-target
pwn:heap-layout-calibrate
pwn:exploit-skeleton
pwn:hardening-map
pwn:tls-state-model
pwn:cfi-bypass-planner
pwn:micro-write-stage
pwn:side-effect-debugger
pwn:cross-stack-layout
pwn:remote-libc-resolver
pwn:exit-handler-planner
pwn:malloc-side-effect-planner
pwn:remote-command-capture
pwn:sandbox-helper-protocol
pwn:path-sanitizer-boundary
pwn:trusted-helper-rewrite
```
