pub mod backend;
pub mod exec;

pub use backend::{detect_backend, which, SandboxBackend};
pub use exec::{
    sandbox_exec, ExitOutcome, MountSpec, SandboxError, SandboxExecOptions, SandboxExecResult,
};
