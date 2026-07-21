use anyhow::{Context, Result};
use std::collections::HashMap;
use std::env;
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
pub(in crate::scan) use try_wait::*;
mod capture_scanner_process_pipes;
mod is_safe_scanner_env_key;
#[cfg(unix)]
mod parent_death_guard;
mod prepared_process_group;
mod scan_cancellation;
mod try_wait;
pub(in crate::scan) use capture_scanner_process_pipes::{
    capture_scanner_process_pipes, join_scanner_process_readers, wait_for_scanner_process,
    ScannerProcessOutput,
};
pub(in crate::scan) use is_safe_scanner_env_key::is_safe_scanner_env_key;
pub(in crate::scan) use is_safe_scanner_env_key::ProcessOutput;
#[cfg(unix)]
pub(in crate::scan) use parent_death_guard::ParentDeathGuard;
pub use prepared_process_group::PreparedProcessGroup;
pub use scan_cancellation::{CancellationDisposition, RegisteredChild, ScanCancellation};
pub(crate) use try_wait::{configure_scanner_process_group, configure_scanner_subprocess_env};
