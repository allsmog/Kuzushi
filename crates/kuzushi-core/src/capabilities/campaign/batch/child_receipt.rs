use super::equivalence::{capture_batch_equivalence, digest_serializable, scan_batch_base_input};
use super::BatchEquivalenceKey;
use crate::{modules::ModuleRegistry, V2Config};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;

pub const SCAN_BATCH_EQUIVALENCE_RECEIPT_FILE: &str = "batch-equivalence.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanBatchChildEquivalenceReceipt {
    pub schema_version: u32,
    pub batch_id: String,
    pub trial: usize,
    pub expected_key: String,
    pub consumed: BatchEquivalenceKey,
}

pub fn verify_scan_batch_child_equivalence(
    root: &Path,
    run_id: &str,
    input: &Value,
    config: &V2Config,
    registry: &ModuleRegistry,
) -> Result<Option<ScanBatchChildEquivalenceReceipt>> {
    let Some((batch_id, trial, expected_key)) = batch_provenance(input)? else {
        return Ok(None);
    };
    let consumed = capture_batch_equivalence(root, &trial_base_input(input), config, registry)?;
    anyhow::ensure!(
        consumed.sha256 == expected_key,
        "scan-batch child refused BatchEquivalenceKey drift (expected {expected_key}, actual {})",
        consumed.sha256
    );
    let receipt = ScanBatchChildEquivalenceReceipt {
        schema_version: 1,
        batch_id,
        trial,
        expected_key,
        consumed,
    };
    persist_child_receipt(root, run_id, &receipt)?;
    Ok(Some(receipt))
}

pub fn load_scan_batch_child_equivalence_receipt(
    root: &Path,
    run_id: &str,
) -> Result<ScanBatchChildEquivalenceReceipt> {
    let (_, body) = crate::run_artifacts::read_run_artifact_text(
        root,
        run_id,
        SCAN_BATCH_EQUIVALENCE_RECEIPT_FILE,
    )
    .require("scan-batch child equivalence receipt")?;
    let receipt: ScanBatchChildEquivalenceReceipt =
        serde_json::from_str(&body).context("scan-batch child equivalence receipt is malformed")?;
    receipt.validate()?;
    Ok(receipt)
}

impl ScanBatchChildEquivalenceReceipt {
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(self.schema_version == 1, "unsupported child receipt schema");
        anyhow::ensure!(
            !self.batch_id.is_empty() && self.trial > 0 && !self.expected_key.is_empty(),
            "scan-batch child equivalence receipt is incomplete"
        );
        anyhow::ensure!(
            digest_serializable(&self.consumed.components)? == self.consumed.sha256,
            "scan-batch child equivalence receipt is not self-authenticating"
        );
        anyhow::ensure!(
            self.consumed.sha256 == self.expected_key,
            "scan-batch child equivalence receipt records drift"
        );
        Ok(())
    }
}

fn batch_provenance(input: &Value) -> Result<Option<(String, usize, String)>> {
    let Some(expected_key) = input.get("batchEquivalenceKey") else {
        return Ok(None);
    };
    let expected_key = required_string(expected_key, "batchEquivalenceKey")?;
    let batch_id = input
        .get("batchId")
        .map(|value| required_string(value, "batchId"))
        .transpose()?
        .context("scan-batch child input is missing batchId")?;
    let trial = input
        .get("trial")
        .and_then(Value::as_u64)
        .map(|value| value as usize)
        .filter(|value| *value > 0)
        .context("scan-batch child input is missing trial")?;
    Ok(Some((batch_id, trial, expected_key)))
}

fn required_string(value: &Value, label: &str) -> Result<String> {
    value
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .with_context(|| format!("scan-batch child input has invalid {label}"))
}

fn trial_base_input(input: &Value) -> Value {
    let threat_model_ref = input.get("threatModelRef").cloned();
    let mut base = scan_batch_base_input(input.clone());
    if let (Some(reference), Some(object)) = (threat_model_ref, base.as_object_mut()) {
        object.insert("threatModelRef".to_string(), reference);
    }
    base
}

fn persist_child_receipt(
    root: &Path,
    run_id: &str,
    receipt: &ScanBatchChildEquivalenceReceipt,
) -> Result<()> {
    receipt.validate()?;
    crate::run_artifacts::write_run_artifact_json(
        root,
        run_id,
        SCAN_BATCH_EQUIVALENCE_RECEIPT_FILE,
        "Scan batch equivalence receipt",
        &serde_json::to_value(receipt)?,
    )?;
    Ok(())
}
