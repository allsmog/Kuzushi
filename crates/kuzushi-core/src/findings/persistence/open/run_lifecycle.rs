use super::*;
use crate::event_log::EventKind;
use crate::storage_v3::writer_actor::{
    DecisionCommand, RunLifecycleWrite, StorageWriterActor, WriterCommand,
};

impl FindingStore {
    pub(crate) fn with_run_lifecycle<T>(
        &self,
        id: &str,
        target: &Path,
        operation: impl FnOnce() -> Result<(T, usize)>,
    ) -> Result<T> {
        self.record_run_started(id, target, "running")?;
        match operation() {
            Ok((value, findings_count)) => {
                self.finish_successful_run(id, findings_count)?;
                Ok(value)
            }
            Err(error) => Err(self.finish_failed_run(id, error)),
        }
    }

    fn finish_successful_run(&self, id: &str, findings_count: usize) -> Result<()> {
        self.record_run_finished(id, "completed", findings_count)
            .inspect_err(|_| {
                let _ = self.record_run_finished(id, "failed", findings_count);
            })
    }

    fn finish_failed_run(&self, id: &str, error: anyhow::Error) -> anyhow::Error {
        match self.record_run_finished(id, "failed", 0) {
            Ok(()) => error,
            Err(terminal_error) => error.context(format!(
                "also could not record failed lifecycle for run {id}: {terminal_error:#}"
            )),
        }
    }

    pub fn record_run_started(&self, id: &str, target: &Path, status: &str) -> Result<()> {
        self.record_v3_run_lifecycle(RunLifecycleWrite {
            event_kind: EventKind::RunStarted,
            run_id: id.to_string(),
            target: Some(target.display().to_string()),
            status: status.to_string(),
            findings_count: None,
            terminal_item_hash: None,
            actor: "finding-store".to_string(),
        })?;
        Ok(())
    }

    pub fn insert_scan_run(&self, id: &str, target: &Path, status: &str) -> Result<()> {
        self.record_run_started(id, target, status)
    }

    pub fn record_run_finished(&self, id: &str, status: &str, findings_count: usize) -> Result<()> {
        self.record_v3_run_lifecycle(RunLifecycleWrite {
            event_kind: completed_run_event_kind(status),
            run_id: id.to_string(),
            target: None,
            status: status.to_string(),
            findings_count: Some(findings_count as u64),
            terminal_item_hash: None,
            actor: "finding-store".to_string(),
        })?;
        // Only a fully-completed re-scan can honestly retire a prior finding.
        // Allowlist (not `!= failed`) so a future canceled/partial status can
        // never silently enable reconciliation on this honesty-critical path.
        if status == "completed" && self.v3_storage_paths().is_some() {
            self.reconcile_disappeared_findings(id)?;
        }
        Ok(())
    }

    pub fn complete_scan_run(&self, id: &str, status: &str, findings_count: usize) -> Result<()> {
        self.record_run_finished(id, status, findings_count)
    }

    /// The recorded lifecycle status of a run, if the run is known.
    pub(crate) fn run_status(&self, run_id: &str) -> Result<Option<String>> {
        self.conn
            .query_row(
                "select status from run_states where run_id = ?1",
                params![run_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .context("Could not load run status")
    }

    pub fn latest_run_id(&self) -> Result<Option<String>> {
        let mut stmt = self.conn.prepare(
            r#"
            select run_id
            from run_states
            order by updated_seq desc, run_id desc
            limit 1
            "#,
        )?;
        match stmt.query_row([], |row| row.get(0)) {
            Ok(id) => Ok(Some(id)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error).context("Could not load latest run id"),
        }
    }

    fn record_v3_run_lifecycle(&self, run: RunLifecycleWrite) -> Result<()> {
        let (event_log_dir, db_path) = self.required_v3_storage_paths("record run lifecycle")?;
        StorageWriterActor::commit_blocking(
            event_log_dir,
            db_path,
            WriterCommand::Decision(DecisionCommand::RecordRunLifecycle(run)),
        )?;
        Ok(())
    }
}

fn completed_run_event_kind(status: &str) -> EventKind {
    if status == "failed" {
        EventKind::RunFailed
    } else {
        EventKind::RunCompleted
    }
}
