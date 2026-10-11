use super::*;
use crate::findings::{
    validate_relationship_selection, FindingRelationshipState, FINDING_RELATIONSHIP_BATCH_SUBJECT,
};

impl StorageWriter {
    pub(in crate::storage_v3::writer_actor) fn record_finding_relationship_batch(
        &mut self,
        selected: Vec<FindingRelationship>,
        records: Vec<FindingRelationship>,
    ) -> Result<WriteReceipt> {
        require_state(self.lifecycle.state(), WriterActorState::Live)?;
        validate_relationship_selection(&records)?;
        validate_relationship_selection(&selected)?;
        anyhow::ensure!(
            selected.len() == records.len(),
            "Relationship batch selection changed"
        );
        for (original, record) in selected.iter().zip(&records) {
            validate_reviewed_record(&self.projection.conn, original, record)?;
        }
        self.record_audit_event(AuditWrite {
            event_kind: EventKind::DiagnosticRecorded,
            actor: "human".into(),
            run_id: None,
            stable_fp: None,
            subject: Some(FINDING_RELATIONSHIP_BATCH_SUBJECT.into()),
            summary: format!(
                "Reviewed {} finding relationships atomically",
                records.len()
            ),
            details: json!({"schemaVersion":1,"records":records}),
        })
    }
}

fn validate_reviewed_record(
    conn: &rusqlite::Connection,
    selected: &FindingRelationship,
    record: &FindingRelationship,
) -> Result<()> {
    anyhow::ensure!(
        record.author == "human" && record.state != FindingRelationshipState::Proposed,
        "Relationship batch requires reviewed operator decisions"
    );
    let current = crate::findings::persistence::relationship_reads::latest(conn, &record.id)?;
    anyhow::ensure!(
        current.as_ref() == Some(selected),
        "Relationship selection changed; refresh before deciding"
    );
    validate_revision(current.as_ref(), record, selected.revision)?;
    if record.state == FindingRelationshipState::Accepted {
        validate_current_endpoints(conn, record)?;
    }
    Ok(())
}
