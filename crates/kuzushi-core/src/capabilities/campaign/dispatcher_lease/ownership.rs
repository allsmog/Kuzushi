use anyhow::{Context, Result};
use std::fs::File;
use std::path::Path;

/// Probe the existing controller lease without creating or rewriting state.
/// Ownership does not establish progress or authenticate an assessment.
pub(crate) fn batch_controller_owns_publication(root: &Path, batch_id: &str) -> Result<bool> {
    let Some(file) = open_existing_controller_lock(root, batch_id)? else {
        return Ok(false);
    };
    match file.try_lock_shared() {
        Ok(()) => Ok(false),
        Err(std::fs::TryLockError::WouldBlock) => Ok(true),
        Err(std::fs::TryLockError::Error(error)) => {
            Err(error).context("could not probe study controller ownership")
        }
    }
}

fn open_existing_controller_lock(root: &Path, batch_id: &str) -> Result<Option<File>> {
    crate::capabilities::campaign::validate_scan_batch_id(batch_id)?;
    let workspace = crate::WorkspaceTarget::new(root)?;
    let path = crate::capabilities::campaign::campaign_dir(workspace.root(), batch_id)
        .join(".batch-controller.lock");
    match crate::bounded_file::open_regular_file_within(workspace.root(), &path) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("could not open existing study controller ownership"),
    }
}

#[cfg(test)]
mod tests;
