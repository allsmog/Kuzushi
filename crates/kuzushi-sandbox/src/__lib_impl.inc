#[path = "backend/implementation.inc"]
pub mod backend;
#[path = "exec/implementation.inc"]
pub mod exec;

pub use backend::{detect_backend, which, SandboxBackend};
pub use exec::{
    sandbox_exec, ExitOutcome, MountSpec, SandboxError, SandboxExecOptions, SandboxExecResult,
};
