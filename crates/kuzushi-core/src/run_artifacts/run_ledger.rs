use super::run_paths::ensure_run_dir;
use crate::file_lock::ExclusiveFileLock;
use anyhow::Result;
use std::path::Path;

const RUN_LEDGER_LOCK: &str = ".ledger.lock";
const RUN_TERMINAL_LOCK: &str = ".terminal.lock";
const LATEST_POINTER_LOCK: &str = ".latest.lock";
const RUN_HISTORY_INDEX_LOCK: &str = ".run-history-index.lock";

pub(super) fn acquire_run_ledger_lock(
    target: impl AsRef<Path>,
    run_id: &str,
) -> Result<ExclusiveFileLock> {
    let run_dir = ensure_run_dir(target, run_id)?;
    ExclusiveFileLock::acquire(&run_dir.join(RUN_LEDGER_LOCK))
}

pub(super) fn acquire_run_terminal_lock(
    target: impl AsRef<Path>,
    run_id: &str,
) -> Result<ExclusiveFileLock> {
    let run_dir = ensure_run_dir(target, run_id)?;
    ExclusiveFileLock::acquire(&run_dir.join(RUN_TERMINAL_LOCK))
}

pub(super) fn acquire_latest_pointer_lock(target: impl AsRef<Path>) -> Result<ExclusiveFileLock> {
    let state_dir = crate::workspace::initialize_workspace_state(target.as_ref())?;
    ExclusiveFileLock::acquire(&state_dir.join(LATEST_POINTER_LOCK))
}

pub(super) fn acquire_run_history_index_lock(
    target: impl AsRef<Path>,
) -> Result<ExclusiveFileLock> {
    let state_dir = crate::workspace::initialize_workspace_state(target.as_ref())?;
    ExclusiveFileLock::acquire(&state_dir.join(RUN_HISTORY_INDEX_LOCK))
}
