//! Serialize relationship revisions through the existing single writer.
use super::*;
use crate::findings::{FindingRelationship, FINDING_RELATIONSHIP_SUBJECT};

mod batch;

impl StorageWriter {
    pub(super) fn record_finding_relationship(
        &mut self,
        record: FindingRelationship,
        expected_revision: u64,
    ) -> Result<WriteReceipt> {
        require_state(self.lifecycle.state(), WriterActorState::Live)?;
        record.validate()?;
        validate_recorded_observations(&self.projection.conn, &record)?;
        let current = crate::findings::persistence::relationship_reads::latest(
            &self.projection.conn,
            &record.id,
        )?;
        validate_revision(current.as_ref(), &record, expected_revision)?;
        self.record_audit_event(AuditWrite {
            event_kind: EventKind::DiagnosticRecorded,
            actor: record.author.clone(),
            run_id: None,
            stable_fp: Some(record.from.stable_key.clone()),
            subject: Some(FINDING_RELATIONSHIP_SUBJECT.into()),
            summary: format!("Finding relationship {:?}: {:?}", record.kind, record.state),
            details: serde_json::to_value(record)?,
        })
    }
}

fn validate_recorded_observations(
    conn: &rusqlite::Connection,
    record: &FindingRelationship,
) -> Result<()> {
    if record.author != "model" {
        return Ok(());
    }
    validate_current_endpoints(conn, record)
}

fn validate_current_endpoints(
    conn: &rusqlite::Connection,
    record: &FindingRelationship,
) -> Result<()> {
    for endpoint in [&record.from, &record.to] {
        let current =
            crate::findings::persistence::relationship_reads::latest_observation_endpoint(
                conn,
                &endpoint.stable_key,
            )?;
        anyhow::ensure!(
            current.as_ref() == Some(endpoint),
            "finding observation changed during relationship review; refresh before deciding"
        );
    }
    Ok(())
}

fn validate_revision(
    current: Option<&FindingRelationship>,
    next: &FindingRelationship,
    expected: u64,
) -> Result<()> {
    let actual = current.map_or(0, |record| record.revision);
    anyhow::ensure!(
        actual == expected,
        "relationship changed; refresh before deciding"
    );
    anyhow::ensure!(
        next.revision
            == expected
                .checked_add(1)
                .context("relationship revision exhausted")?,
        "relationship revision is invalid"
    );
    if let Some(current) = current {
        anyhow::ensure!(
            current.from == next.from && current.to == next.to && current.kind == next.kind,
            "relationship source binding changed"
        );
    }
    Ok(())
}
