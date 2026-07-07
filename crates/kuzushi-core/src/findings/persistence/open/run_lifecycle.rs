use super::*;
use crate::event_log::EventKind;
use crate::storage_v3::writer_actor::{
    DecisionCommand, RunLifecycleWrite, StorageWriterActor, WriterCommand,
};

impl FindingStore {
    pub fn record_run_started(&self, id: &str, target: &Path, status: &str) -> Result<()> {
        self.record_v3_run_lifecycle(RunLifecycleWrite {
            event_kind: EventKind::RunStarted,
            run_id: id.to_string(),
            target: Some(target.display().to_string()),
            status: status.to_string(),
            findings_count: None,
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
            actor: "finding-store".to_string(),
        })?;
        Ok(())
    }

    pub fn complete_scan_run(&self, id: &str, status: &str, findings_count: usize) -> Result<()> {
        self.record_run_finished(id, status, findings_count)
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
