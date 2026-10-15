#[cfg(windows)]
use anyhow::Context;
use anyhow::Result;
use std::collections::HashMap;
use std::env;
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(test)]
use std::time::Duration;
pub(in crate::scan) use try_wait::*;
mod is_safe_scanner_env_key;
#[cfg(unix)]
mod parent_death_guard;
mod prepared_process_group;
mod scan_cancellation;
mod scanner_process_output;
mod try_wait;
pub(in crate::scan) use is_safe_scanner_env_key::is_safe_scanner_env_key;
#[cfg(unix)]
pub(in crate::scan) use parent_death_guard::ParentDeathGuard;
pub use prepared_process_group::PreparedProcessGroup;
pub use scan_cancellation::{CancellationDisposition, RegisteredChild, ScanCancellation};
pub(in crate::scan) use scanner_process_output::ScannerProcessOutput;
pub(crate) use try_wait::{configure_scanner_process_group, configure_scanner_subprocess_env};
