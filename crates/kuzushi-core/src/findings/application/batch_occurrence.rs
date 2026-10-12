//! Derived repeatability report for one dedicated scan batch.
//!
//! The report is rebuilt from the immutable plan, dispatcher queue, and raw
//! trial findings. It is never another mutable source of finding truth.

use super::super::domain::FindingIdentityBasis;
use super::super::persistence::FindingStore;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;

mod fold;
mod gate_binding;
mod load;
#[cfg(test)]
mod tests;

pub use fold::finding_projection_key;
use fold::{occurrence_rows, LogicalTrialCounts};
pub use gate_binding::derive_batch_gate_binding;
use load::{
    hydrate_finding_run_ids, read_batch_document, read_optional_batch_document, required_string,
    trial_reports, validate_batch_trial_receipts,
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityFoldPolicy {
    #[default]
    Legacy,
    Safe,
    Aggressive,
}

impl IdentityFoldPolicy {
    pub fn parse(value: Option<&str>) -> Result<Self> {
        match value.unwrap_or("legacy").trim() {
            "legacy" => Ok(Self::Legacy),
            "safe" => Ok(Self::Safe),
            "aggressive" => Ok(Self::Aggressive),
            other => anyhow::bail!("unknown identityFold policy {other:?}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchTrialReport {
    pub trial: usize,
    pub job_id: String,
    pub state: String,
    pub attempts: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attempt_run_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub finding_run_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchOccurrenceRow {
    pub fold_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_basis: Option<FindingIdentityBasis>,
    pub seen: usize,
    pub completed: usize,
    pub planned: usize,
    pub failed: usize,
    pub severities: Vec<String>,
    pub locations: Vec<String>,
    pub titles: Vec<String>,
    pub fingerprints: Vec<String>,
    pub run_ids: Vec<String>,
    pub representative_fingerprint: String,
    pub representative_title: String,
    pub representative_severity: String,
    pub representative_location: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchOccurrenceReport {
    pub schema_version: u32,
    pub batch_id: String,
    pub equivalence_key: String,
    pub identity_fold: IdentityFoldPolicy,
    pub planned: usize,
    pub completed: usize,
    pub failed: usize,
    pub pending: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gate: Option<crate::capabilities::campaign::ScanBatchGateOutcome>,
    pub trials: Vec<BatchTrialReport>,
    pub rows: Vec<BatchOccurrenceRow>,
}

impl BatchOccurrenceReport {
    /// Ledger membership from every recorded attempt, including incomplete work.
    /// Recurrence rows and completed-pass counts remain separate.
    pub fn retained_observation_fingerprints(
        &self,
        root: &Path,
        store: &FindingStore,
    ) -> Result<std::collections::BTreeSet<String>> {
        let runs = crate::run_artifacts::scan_finding_run_refs(root, &self.all_attempt_run_ids())?;
        Ok(store
            .list_distinct_findings_for_scan_ids_with_identity_policy(&runs, self.identity_fold)?
            .into_iter()
            .map(|finding| finding.fingerprint)
            .collect())
    }

    pub fn completed_run_ids(&self) -> Vec<String> {
        let mut run_ids = self
            .trials
            .iter()
            .filter(|trial| trial.state == "completed")
            .flat_map(|trial| trial.finding_run_ids.iter().cloned())
            .collect::<Vec<_>>();
        run_ids.sort();
        run_ids.dedup();
        run_ids
    }

    pub fn all_attempt_run_ids(&self) -> Vec<String> {
        let mut run_ids = self
            .trials
            .iter()
            .flat_map(|trial| trial.attempt_run_ids.iter().cloned())
            .collect::<Vec<_>>();
        run_ids.sort();
        run_ids.dedup();
        run_ids
    }

    pub fn output(&self) -> String {
        let mut lines = vec![self.summary_line()];
        if let Some(gate) = &self.gate {
            lines.push(format!(
                "gate {} · blocking {} · completed runs {}",
                gate.status.as_str(),
                gate.blocking_safe_fold_count,
                gate.completed_run_ids.len()
            ));
        }
        if self.rows.is_empty() {
            lines.push("no findings observed in completed trials".to_string());
        } else {
            lines.push(
                "OCCURRENCE                              SEVERITY  LOCATION  TITLE".to_string(),
            );
            lines.extend(self.rows.iter().map(BatchOccurrenceRow::output_line));
        }
        lines.join("\n")
    }

    fn summary_line(&self) -> String {
        format!(
            "batch {} · completed {} / planned {} · failed {} · pending {} · {}",
            self.batch_id,
            self.completed,
            self.planned,
            self.failed,
            self.pending,
            self.equivalence_key
        )
    }
}

impl BatchOccurrenceRow {
    fn output_line(&self) -> String {
        let occurrence = format!(
            "seen {} / completed {} · planned {} · failed {}",
            self.seen, self.completed, self.planned, self.failed
        );
        format!(
            "{occurrence:<39} {:<9} {}  {}{}",
            self.representative_severity,
            self.representative_location,
            self.representative_title,
            variance_suffix(self)
        )
    }
}

fn variance_suffix(row: &BatchOccurrenceRow) -> String {
    let variants = [
        ("severity", row.severities.len()),
        ("location", row.locations.len()),
        ("title", row.titles.len()),
    ]
    .into_iter()
    .filter(|(_, count)| *count > 1)
    .map(|(label, count)| format!("{label}×{count}"))
    .collect::<Vec<_>>();
    (!variants.is_empty())
        .then(|| format!(" [{}]", variants.join(", ")))
        .unwrap_or_default()
}

pub fn derive_batch_occurrence_report(
    root: &Path,
    batch_id: &str,
    store: &FindingStore,
) -> Result<BatchOccurrenceReport> {
    derive_batch_occurrence_report_inner(root, batch_id, store, true)
}

pub fn derive_batch_occurrence_report_for_controller(
    root: &Path,
    batch_id: &str,
    store: &FindingStore,
) -> Result<BatchOccurrenceReport> {
    derive_batch_occurrence_report_inner(root, batch_id, store, false)
}

fn derive_batch_occurrence_report_inner(
    root: &Path,
    batch_id: &str,
    store: &FindingStore,
    hydrate_gate: bool,
) -> Result<BatchOccurrenceReport> {
    let plan = read_batch_document(root, batch_id, "plan.json")?;
    let checked =
        crate::capabilities::campaign::validate_scan_batch_execution_plan(batch_id, &plan)?;
    let queue = read_optional_batch_document(root, batch_id, "queue.json")?;
    let mut report = derive_occurrence_from_documents(
        root,
        batch_id,
        store,
        &plan,
        queue.as_ref(),
        checked.equivalence_key,
    )?;
    if hydrate_gate {
        report.gate = load_batch_gate(root, batch_id, &plan, store, &report)?;
    }
    Ok(report)
}

pub(super) fn derive_occurrence_from_documents(
    root: &Path,
    batch_id: &str,
    store: &FindingStore,
    plan: &Value,
    queue: Option<&Value>,
    equivalence_key: String,
) -> Result<BatchOccurrenceReport> {
    let policy = IdentityFoldPolicy::parse(plan.get("identityFold").and_then(Value::as_str))?;
    let mut trials = trial_reports(plan, queue);
    hydrate_finding_run_ids(root, &mut trials);
    validate_batch_trial_receipts(root, plan, queue, &trials)?;
    let counts = LogicalTrialCounts::from_trials(&trials);
    Ok(BatchOccurrenceReport {
        schema_version: 1,
        batch_id: batch_id.to_string(),
        equivalence_key,
        identity_fold: policy,
        planned: counts.planned,
        completed: counts.completed,
        failed: counts.failed,
        pending: counts.pending,
        gate: None,
        rows: occurrence_rows(store, &trials, policy, counts)?,
        trials,
    })
}

pub(super) fn read_occurrence_queue(root: &Path, id: &str) -> Result<Option<Value>> {
    read_optional_batch_document(root, id, "queue.json")
}

fn load_batch_gate(
    root: &Path,
    batch_id: &str,
    plan: &Value,
    store: &FindingStore,
    report: &BatchOccurrenceReport,
) -> Result<Option<crate::capabilities::campaign::ScanBatchGateOutcome>> {
    let Some(document) = read_optional_batch_document(root, batch_id, "gate.json")? else {
        return Ok(None);
    };
    let outcome = serde_json::from_value(document)?;
    validate_loaded_batch_gate(batch_id, plan, &outcome)?;
    let (binding, blocking_count) = derive_batch_gate_binding(
        store,
        report,
        outcome.policy.fail_on,
        outcome.binding.sarif_path.as_deref(),
    )?;
    anyhow::ensure!(
        outcome.binding == binding && outcome.blocking_safe_fold_count == blocking_count,
        "batch gate is stale for the current trial/finding/SARIF state"
    );
    Ok(Some(outcome))
}

fn validate_loaded_batch_gate(
    batch_id: &str,
    plan: &Value,
    outcome: &crate::capabilities::campaign::ScanBatchGateOutcome,
) -> Result<()> {
    use crate::capabilities::campaign::ScanBatchGatePolicy;
    outcome.validate()?;
    anyhow::ensure!(
        outcome.batch_id == batch_id,
        "batch gate id disagrees with its directory"
    );
    anyhow::ensure!(
        outcome.equivalence_key == required_string(plan, "equivalenceKey")?,
        "batch gate equivalence key disagrees with its immutable plan"
    );
    let planned: ScanBatchGatePolicy = serde_json::from_value(
        plan.get("gatePolicy")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("scan-batch plan is missing gatePolicy"))?,
    )?;
    anyhow::ensure!(
        outcome.policy == planned,
        "batch gate policy disagrees with its immutable plan"
    );
    Ok(())
}
