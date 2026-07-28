use super::*;
use crate::storage_v3::writer_actor::{
    DecisionCommand, RekeyWrite, StorageWriterActor, WriterCommand,
};
use std::collections::BTreeSet;

/// Decision-forwarding through `rekey_edges` requires confidence >= 0.8, so a
/// model-dedupe rekey never persists below that floor.
pub const MODEL_REKEY_CONFIDENCE_FLOOR_MILLIS: u16 = 800;

const MAX_REKEY_HOPS: usize = 8;

/// An evidence-backed model-dedupe link: the duplicate's stable key rekeys onto the
/// canonical's stable key, with the evidence the projector needs to attach
/// the duplicate fingerprint to the canonical identity.
#[derive(Debug, Clone, PartialEq)]
pub struct ModelRekeyRequest {
    pub duplicate_stable_key: String,
    pub canonical_stable_key: String,
    pub duplicate_fingerprint: String,
    pub canonical_fingerprint: String,
    pub canonical_identity_id: Option<String>,
    pub root_cause_summary: String,
    pub confidence: f64,
    pub run_id: Option<String>,
}

impl ModelRekeyRequest {
    fn confidence_millis(&self) -> u16 {
        let millis = (self.confidence.clamp(0.0, 1.0) * 1000.0).round() as u16;
        millis.max(MODEL_REKEY_CONFIDENCE_FLOOR_MILLIS)
    }

    fn evidence(&self) -> serde_json::Value {
        serde_json::json!({
            "rootCauseSummary": self.root_cause_summary,
            "duplicateFingerprint": self.duplicate_fingerprint,
            "canonicalFingerprint": self.canonical_fingerprint,
            "canonicalIdentityId": self.canonical_identity_id,
            "runId": self.run_id,
        })
    }
}

impl FindingStore {
    /// Stable keys that already carry an outgoing rekey edge — these rows are
    /// settled duplicates and drop out of dedupe candidate selection.
    pub fn rekeyed_stable_keys(&self) -> Result<BTreeSet<String>> {
        let mut stmt = self
            .conn
            .prepare("select distinct old_fp from rekey_edges")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<BTreeSet<_>>>()
            .context("Could not list rekeyed stable keys")
    }

    /// Distinct direct rekey targets recorded for a stable key.
    pub fn rekey_targets_for(&self, stable_key: &str) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("select distinct new_fp from rekey_edges where old_fp = ?1 order by new_fp")?;
        let rows = stmt.query_map(params![stable_key], |row| row.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not list rekey targets")
    }

    /// Terminal target of the rekey chain starting at `stable_key`. Follows
    /// unambiguous edges only (a key with conflicting targets terminates the
    /// walk), is cycle-guarded, and stops after eight hops.
    pub fn resolve_rekey_target(&self, stable_key: &str) -> Result<String> {
        let mut current = stable_key.to_string();
        let mut seen = BTreeSet::new();
        for _ in 0..MAX_REKEY_HOPS {
            if !seen.insert(current.clone()) {
                anyhow::bail!("rekey chain for {stable_key} contains a cycle at {current}");
            }
            let targets = self.rekey_targets_for(&current)?;
            match targets.as_slice() {
                [next] => current = next.clone(),
                _ => return Ok(current),
            }
        }
        Ok(current)
    }

    /// Append a model-dedupe `FindingRekeyed` event. Callers own idempotency:
    /// event re-emission is NOT idempotent, so an existing edge to the same
    /// terminal must be skipped before calling this.
    pub fn record_model_rekey(&self, request: &ModelRekeyRequest) -> Result<()> {
        let (event_log_dir, db_path) =
            self.required_v3_storage_paths("record model-dedupe rekeys")?;
        StorageWriterActor::commit_blocking(
            event_log_dir,
            db_path,
            WriterCommand::Decision(DecisionCommand::RekeyFinding(RekeyWrite {
                old_fp: request.duplicate_stable_key.clone(),
                new_fp: request.canonical_stable_key.clone(),
                method: "model-dedupe".to_string(),
                confidence_millis: request.confidence_millis(),
                actor: "triage:dedupe".to_string(),
                evidence: Some(request.evidence()),
            })),
        )?;
        Ok(())
    }
}
