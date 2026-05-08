mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod items_1;
mod items_2;
mod items_3;
/// What happened to the child.

/// Build argv for the chosen backend and run the child to completion.

/// Build argv for the requested backend. Public for testing — verify
/// that the right flags appear in the right order without spawning.

#[cfg(test)]
mod tests;

pub use items_1::ExitOutcome;
pub use items_1::MountSpec;
pub use items_1::SandboxError;
pub use items_1::SandboxExecOptions;
pub use items_1::SandboxExecResult;
pub use items_2::build_argv;
pub use items_2::sandbox_exec;
