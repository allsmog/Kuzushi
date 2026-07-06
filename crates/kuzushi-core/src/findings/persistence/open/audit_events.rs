use super::*;
use crate::event_log::EventKind;
use crate::storage_v3::writer_actor::{
    AuditWrite, DecisionCommand, StorageWriterActor, WriterCommand,
};
use serde_json::Value;

impl FindingStore {
    pub fn record_finding_audit_event(
        &self,
        finding_id: i64,
        actor: impl Into<String>,
        subject: impl Into<String>,
        summary: impl Into<String>,
        details: Value,
    ) -> Result<()> {
        let Some(target) = self.v3_target_for_finding(finding_id, "finding audit event")? else {
            return Ok(());
        };
        StorageWriterActor::commit_blocking(
            target.event_log_dir,
            target.db_path,
            WriterCommand::Decision(DecisionCommand::RecordAudit(AuditWrite {
                event_kind: EventKind::DiagnosticRecorded,
                actor: actor.into(),
                run_id: None,
                stable_fp: Some(target.stable_fp),
                subject: Some(subject.into()),
                summary: summary.into(),
                details,
            })),
        )?;
        Ok(())
    }
}
