use super::*;
use crate::findings::persistence::relationship_reads;
use crate::findings::{
    FindingRelationship, FindingRelationshipEndpoint, FindingRelationshipKind,
    FindingRelationshipState,
};
use crate::storage_v3::writer_actor::{DecisionCommand, StorageWriterActor, WriterCommand};

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingRelationshipPage {
    pub rows: Vec<FindingRelationship>,
    pub has_more: bool,
    pub offset: usize,
}

impl FindingStore {
    pub fn review_finding_relationship_batch(
        &self,
        selected: &[FindingRelationship],
        state: FindingRelationshipState,
        note: &str,
    ) -> Result<Vec<FindingRelationship>> {
        crate::findings::validate_relationship_selection(selected)?;
        let records = selected
            .iter()
            .map(|record| record.review(state, note.trim().into(), record.revision))
            .collect::<Result<Vec<_>>>()?;
        let (log, db) = self.required_v3_storage_paths("finding relationship batch")?;
        StorageWriterActor::commit_blocking(
            log,
            db,
            WriterCommand::Decision(DecisionCommand::FindingRelationshipBatch {
                selected: selected.to_vec(),
                records: records.clone(),
            }),
        )?;
        Ok(records)
    }

    pub fn propose_recorded_finding_relationship(
        &self,
        from: &Finding,
        to: &Finding,
        kind: FindingRelationshipKind,
        note: &str,
        confidence: Option<f64>,
    ) -> Result<FindingRelationship> {
        let endpoint = |finding: &Finding| -> Result<FindingRelationshipEndpoint> {
            Ok(FindingRelationshipEndpoint {
                stable_key: finding
                    .identity_id
                    .clone()
                    .unwrap_or_else(|| finding.fingerprint.clone()),
                fingerprint: finding.fingerprint.clone(),
                finding_id: finding.id.context("finding id missing")?,
                run_id: finding.scan_id.clone(),
            })
        };
        let record = FindingRelationship::new(
            endpoint(from)?,
            endpoint(to)?,
            kind,
            note.trim().into(),
            "model".into(),
        )?;
        self.record_model_relationship(record, confidence)
    }
    pub fn finding_relationship(&self, id: &str) -> Result<Option<FindingRelationship>> {
        relationship_reads::latest(&self.conn, id)
    }

    pub fn finding_relationships(
        &self,
        finding_id: Option<i64>,
        limit: usize,
        offset: usize,
    ) -> Result<FindingRelationshipPage> {
        anyhow::ensure!(
            (1..=200).contains(&limit) && offset <= 1_000_000,
            "relationship page limit or offset is invalid"
        );
        let stable_key = finding_id
            .map(|id| {
                self.relationship_endpoint(id)
                    .map(|endpoint| endpoint.stable_key)
            })
            .transpose()?;
        let mut rows =
            relationship_reads::page(&self.conn, stable_key.as_deref(), limit + 1, offset)?;
        let has_more = rows.len() > limit;
        rows.truncate(limit);
        Ok(FindingRelationshipPage {
            rows,
            has_more,
            offset,
        })
    }

    pub fn propose_finding_relationship(
        &self,
        from: i64,
        to: i64,
        kind: FindingRelationshipKind,
        note: &str,
        confidence: Option<f64>,
    ) -> Result<FindingRelationship> {
        let record = FindingRelationship::new(
            self.relationship_endpoint(from)?,
            self.relationship_endpoint(to)?,
            kind,
            note.trim().into(),
            "model".into(),
        )?;
        self.record_model_relationship(record, confidence)
    }

    fn record_model_relationship(
        &self,
        mut record: FindingRelationship,
        confidence: Option<f64>,
    ) -> Result<FindingRelationship> {
        record.confidence = confidence;
        record.validate()?;
        if let Some(existing) = self.finding_relationship(&record.id)? {
            return Ok(existing);
        }
        self.commit_finding_relationship(&record, 0)?;
        self.finding_relationship(&record.id)?
            .context("relationship commit has no readable record")
    }

    pub fn review_finding_relationship(
        &self,
        id: &str,
        state: FindingRelationshipState,
        note: &str,
        expected_revision: u64,
    ) -> Result<FindingRelationship> {
        let current = self
            .finding_relationship(id)?
            .context("relationship no longer exists; refresh before deciding")?;
        let reviewed = current.review(state, note.trim().into(), expected_revision)?;
        self.commit_finding_relationship(&reviewed, expected_revision)?;
        Ok(reviewed)
    }

    fn relationship_endpoint(&self, id: i64) -> Result<FindingRelationshipEndpoint> {
        let target = self
            .v3_target_for_finding(id, "finding relationship")?
            .context("relationship requires an existing finding")?;
        Ok(FindingRelationshipEndpoint {
            stable_key: target.stable_fp,
            fingerprint: target.fingerprint,
            finding_id: id,
            run_id: target.scan_id,
        })
    }

    fn commit_finding_relationship(
        &self,
        record: &FindingRelationship,
        expected_revision: u64,
    ) -> Result<()> {
        let (log, db) = self.required_v3_storage_paths("finding relationship")?;
        StorageWriterActor::commit_blocking(
            log,
            db,
            WriterCommand::Decision(DecisionCommand::FindingRelationship {
                record: record.clone(),
                expected_revision,
            }),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
