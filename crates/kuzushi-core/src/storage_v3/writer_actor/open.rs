//! Writer recovery keeps source-index lock waits cooperative.
use super::*;

impl StorageWriter {
    pub(super) fn open_cancellable(
        log_dir: &Path,
        projection_path: &Path,
        canceled: &dyn Fn() -> bool,
    ) -> Result<Self> {
        anyhow::ensure!(!canceled(), "Storage writer startup was canceled");
        let (log_dir, projection_path) = normalize_storage_paths(log_dir, projection_path)?;
        initialize_workspace_storage(&log_dir, &projection_path)?;
        let ownership = crate::file_lock::ExclusiveFileLock::acquire_cancellable(
            &log_dir.join(".storage-writer.lock"),
            canceled,
        )?;
        let log = EventLog::open(&log_dir)?;
        log.verify_chain()?;
        anyhow::ensure!(!canceled(), "Storage writer recovery was canceled");
        let projection = ProjectionDb::open(&projection_path)?;
        let mut lifecycle = WriterLifecycle::recovering();
        lifecycle.recover(log.head_seq()?, projection.meta()?.applied_seq)?;
        let mut writer = Self {
            _ownership: ownership,
            log,
            projection,
            lifecycle,
        };
        writer.replay_projection()?;
        anyhow::ensure!(!canceled(), "Storage writer recovery was canceled");
        Ok(writer)
    }
}
