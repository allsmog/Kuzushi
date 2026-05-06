//! Process sandbox primitive used by Kuzushi's verify pipeline.
//!
//! Three backends, in order of preference:
//! 1. **Bubblewrap** (`bwrap`) — Linux-only, namespace isolation, no root
//!    needed. Read-only mounts of `/usr`, `/lib`, `/lib64`, `/bin`,
//!    `/etc/alternatives`; tmpfs `/tmp` and `/work`; `--unshare-all`,
//!    `--cap-drop ALL`, no network unless explicitly allowed.
//! 2. **Podman** rootless container — fallback when bwrap is missing
//!    but a container runtime is. `--read-only`, `--cap-drop=ALL`,
//!    `--network=none`, ulimit + memory caps.
//! 3. **Plain** subprocess — last resort. No isolation; only allowed
//!    when the operator explicitly opts in. Used for unit tests too.
//!
//! Output is capped at 1 MiB per stream (truncated with a marker line),
//! and a hard wallclock timeout kills the child if it runs over.
//!
//! This is a Rust port of `src/fuzz/sandbox.ts` from the TypeScript
//! tree, with the same backend selection logic and mount semantics.

pub mod backend;
pub mod exec;

pub use backend::{detect_backend, which, SandboxBackend};
pub use exec::{
    sandbox_exec, ExitOutcome, MountSpec, SandboxError, SandboxExecOptions, SandboxExecResult,
};
