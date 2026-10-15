//! Compare-and-append relevance without writing finding or decision projections.
use super::*;
use crate::findings::persistence::goal_reads;
use crate::findings::{FindingGoalAssessment, GOAL_RELEVANCE_SUBJECT};

impl StorageWriter {
    pub(super) fn record_goal_assessment(
        &mut self,
        record: FindingGoalAssessment,
        expected_revision: u64,
    ) -> Result<WriteReceipt> {
        require_state(self.lifecycle.state(), WriterActorState::Live)?;
        record.validate()?;
        let current = goal_reads::latest(&self.projection.conn, &record.id)?;
        anyhow::ensure!(
            current.as_ref().map_or(0, |row| row.revision) == expected_revision,
            "Goal relevance changed; refresh before saving. Your reason is retained."
        );
        anyhow::ensure!(
            record.revision
                == expected_revision
                    .checked_add(1)
                    .context("Goal revision exhausted")?,
            "Invalid goal relevance revision"
        );
        anyhow::ensure!(
            goal_reads::basis(&self.projection.conn, record.basis.finding_id)? == record.basis,
            "Finding observation changed; refresh and reassess goal relevance"
        );
        self.record_audit_event(AuditWrite {
            event_kind: EventKind::DiagnosticRecorded,
            actor: record.author.clone(),
            run_id: Some(record.basis.run_id.clone()),
            stable_fp: Some(record.basis.stable_key.clone()),
            subject: Some(GOAL_RELEVANCE_SUBJECT.into()),
            summary: format!("Goal relevance: {}", record.relevance.label()),
            details: serde_json::to_value(record)?,
        })
    }
}
