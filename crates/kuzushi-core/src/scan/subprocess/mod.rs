use anyhow::{Context, Result};
use std::collections::HashMap;
use std::env;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
pub(in crate::scan) use try_wait::*;
mod capture_scanner_process_pipes;
mod is_safe_scanner_env_key;
mod scan_cancellation;
mod try_wait;
pub(in crate::scan) use capture_scanner_process_pipes::{
    capture_scanner_process_pipes, join_scanner_process_readers, wait_for_scanner_process,
};
pub(in crate::scan) use is_safe_scanner_env_key::is_safe_scanner_env_key;
pub(in crate::scan) use is_safe_scanner_env_key::ProcessOutput;
pub use scan_cancellation::{RegisteredChild, ScanCancellation};
pub(crate) use try_wait::{
    child_process_group_id, configure_scanner_process_group, configure_scanner_subprocess_env,
};
