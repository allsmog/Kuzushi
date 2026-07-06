# pwn — binary exploitation workflow support

Operator guide for the `pwn` module: profiling, reverse-engineering,
exploit-state tracking, local calibration, and candidate orchestration for
authorized CTF challenges and binary security testing. It supports the
*workflow* around exploitation — facts, state, and bounded attempts — and
keeps every step as an auditable artifact.

Use it when the target is a binary (ELF challenge, shared object, firmware
extract) rather than a source repository. For source targets, start with
`scan`, `taint-iris-next:dataflow-plan`, or `taint-iris-next:finding-review`
instead.

## Tools

| Tool | What it does | Model? |
| --- | --- | --- |
| `pwn:profile-binary` | ELF/checksec/libc/loader/RPATH/architecture facts for a challenge binary. | no |
| `pwn:reverse` | rev.ng-backed reverse engineering plus host strings/symbol summaries: functions, loops, alloc/free sites, dangerous IO. | no |
| `pwn:state` | Read or update structured exploit state for a binary hash (`read`, `merge`, `write`, `record-failed`). | no |
| `pwn:calibrate-local` | Run a local binary briefly and capture `/proc/<pid>/maps` plus script output for leak/base calibration. | no |
| `pwn:run-candidates` | Record and bound candidate exploit attempts against a local or remote target. | no |
| `pwn:auto-solve` | Plan a full pwn workflow for an arbitrary target with the configured LLM runtime. | yes |

Only `pwn:auto-solve` needs a configured model; everything else is
deterministic and runs offline.

## Typical flow

```bash
# 1. Facts first: protections, libc pairing, architecture.
kuzushi --target . run pwn:profile-binary --input '{"binary":"./chall"}'

# 2. Reverse the interesting surface (rev.ng backend).
kuzushi --target . run pwn:reverse --input '{"binary":"./chall"}'

# 3. Track what you know and what failed across attempts.
kuzushi --target . run pwn:state --input '{"binary":"./chall","action":"read"}'

# 4. Calibrate locally before going remote.
kuzushi --target . run pwn:calibrate-local --input '{"binary":"./chall","script":"AAAA\n"}'

# 5. Bound and record candidate attempts.
kuzushi --target . run pwn:run-candidates --input '{"target":"./chall","stateId":"<from profile>","maxAttempts":10}'
```

In the shell, `use pwn` then `tasks` shows the same tools; the pwn dashboard
view summarizes rounds, primitives, and reverse observations as state
accumulates.

## State and artifacts

`pwn:profile-binary` mints a `stateId` keyed by binary hash. `pwn:state`
owns the structured exploit state (primitives found, strategies failed and
why) so an interrupted session — or a different operator — resumes from
recorded facts instead of re-deriving them. `pwn:run-candidates` enforces
`maxAttempts` so remote targets are never hammered unbounded.

## Notes

- `pwn:reverse` requires the rev.ng backend (`backend: "revng"`, the
  default). The reverse-engineer planning task is preselected only for
  binary/APK targets (see the 組 KUMI-KATA phase picker).
- `pwn:auto-solve` derives its model from the session config; like every
  Kuzushi tool it fails explicitly when no model is configured rather than
  picking one silently.
