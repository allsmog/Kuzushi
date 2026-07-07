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
        if let Some((event_log_dir, db_path)) = self.v3_storage_paths() {
            StorageWriterActor::commit_blocking(
                event_log_dir,
                db_path,
                WriterCommand::Decision(DecisionCommand::RecordRunLifecycle(run)),
            )?;
        } else {
            self.insert_v3_run_lifecycle_projection_direct(&run)?;
        }
        Ok(())
    }

    fn insert_v3_run_lifecycle_projection_direct(&self, run: &RunLifecycleWrite) -> Result<()> {
        let seq = self.next_in_memory_run_seq()?;
        let created_at = now_isoish();
        self.insert_v3_run_event_projection_direct(run, seq, &created_at)?;
        self.upsert_v3_run_state_projection_direct(run, seq, &created_at)
    }

    fn insert_v3_run_event_projection_direct(
        &self,
        run: &RunLifecycleWrite,
        seq: i64,
        created_at: &str,
    ) -> Result<()> {
        self.conn.execute(
            INSERT_V3_RUN_EVENT_PROJECTION_SQL,
            params![
                format!("in-memory-run-{seq}"),
                seq,
                run.run_id,
                run.event_kind.as_str(),
                run.target,
                run.status,
                run.findings_count.map(|value| value as i64),
                run.actor,
                created_at,
                run_payload_json(run),
            ],
        )?;
        Ok(())
    }

    fn upsert_v3_run_state_projection_direct(
        &self,
        run: &RunLifecycleWrite,
        seq: i64,
        created_at: &str,
    ) -> Result<()> {
        let started_seq = (run.event_kind == EventKind::RunStarted).then_some(seq);
        let completed_seq = matches!(
            run.event_kind,
            EventKind::RunCompleted | EventKind::RunFailed
        )
        .then_some(seq);
        self.conn.execute(
            UPSERT_V3_RUN_STATE_PROJECTION_SQL,
            params![
                run.run_id,
                run.target,
                run.status,
                run.findings_count.map(|value| value as i64),
                started_seq,
                completed_seq,
                seq,
                created_at,
            ],
        )?;
        Ok(())
    }

    fn next_in_memory_run_seq(&self) -> Result<i64> {
        self.conn
            .query_row(
                "select coalesce(max(seq), 0) + 1 from run_events",
                [],
                |row| row.get(0),
            )
            .context("Could not allocate in-memory v3 run sequence")
    }
}

const INSERT_V3_RUN_EVENT_PROJECTION_SQL: &str = r#"
insert into run_events(
  event_hash, seq, run_id, event_kind, target, status,
  findings_count, actor, created_at, payload_json
)
values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
"#;

const UPSERT_V3_RUN_STATE_PROJECTION_SQL: &str = r#"
insert into run_states(
  run_id, target, status, findings_count, started_seq,
  completed_seq, updated_seq, updated_at
)
values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
on conflict(run_id) do update set
  target = coalesce(excluded.target, run_states.target),
  status = excluded.status,
  findings_count = coalesce(excluded.findings_count, run_states.findings_count),
  started_seq = coalesce(run_states.started_seq, excluded.started_seq),
  completed_seq = coalesce(excluded.completed_seq, run_states.completed_seq),
  updated_seq = excluded.updated_seq,
  updated_at = excluded.updated_at
"#;

fn completed_run_event_kind(status: &str) -> EventKind {
    if status == "failed" {
        EventKind::RunFailed
    } else {
        EventKind::RunCompleted
    }
}

fn run_payload_json(run: &RunLifecycleWrite) -> String {
    serde_json::json!({
        "runId": run.run_id,
        "target": run.target,
        "status": run.status,
        "findingsCount": run.findings_count,
    })
    .to_string()
}
