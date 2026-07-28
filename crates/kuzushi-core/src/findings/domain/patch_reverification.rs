use crate::content_store::ObjectRef;
use crate::workflow_attempts::TargetContentIdentity;
use anyhow::Result;
use serde::{Deserialize, Serialize};

mod validation;
pub(super) use validation::validate_proof_snapshot_ref;

pub const PATCH_REVERIFICATION_RECEIPT_SCHEMA_VERSION: u16 = 1;
const MAX_RECEIPT_STEPS: usize = 10;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PatchReverificationCaseKind {
    OriginalAttack,
    BenignControl,
    Variant,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PatchReverificationTarget {
    Vulnerable,
    Patched,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PatchEmpiricalOutcome {
    Exploited,
    CleanExit,
    Ambiguous,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PatchDetectorReplayOutcome {
    NotRun,
    NotRediscovered,
    Rediscovered,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PatchReverificationStep {
    pub case_id: String,
    pub case_kind: PatchReverificationCaseKind,
    pub target: PatchReverificationTarget,
    pub input_digest: String,
    pub backend: super::PersistedSandboxBackend,
    pub outcome: PatchEmpiricalOutcome,
    pub reached_sink: bool,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PatchReverificationFileHash {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PatchReverificationReceipt {
    pub schema_version: u16,
    pub application_id: String,
    pub patch_run_id: String,
    pub reverify_run_id: String,
    pub source_identity: TargetContentIdentity,
    pub source_commit: String,
    pub diff_hash: String,
    pub reproducer: ObjectRef,
    pub steps: Vec<PatchReverificationStep>,
    pub detector_tool: String,
    pub detector_run_id: String,
    pub detector_outcome: PatchDetectorReplayOutcome,
    pub start_touched_files: Vec<PatchReverificationFileHash>,
    pub end_touched_files: Vec<PatchReverificationFileHash>,
}

impl PatchReverificationReceipt {
    pub fn validate(&self) -> Result<()> {
        validation::validate(self)
    }

    pub fn validate_for_verified(&self) -> Result<()> {
        validation::validate_for_verified(self)
    }

    pub fn validate_for_record(&self, record: &super::PatchLifecycleRecord) -> Result<()> {
        validation::validate_for_record(self, record)
    }
}

#[cfg(test)]
pub(crate) fn test_verified_receipt(
    record: &super::PatchLifecycleRecord,
    reproducer: ObjectRef,
) -> PatchReverificationReceipt {
    let mut steps = Vec::new();
    for (case_id, case_kind, vulnerable_outcome) in [
        (
            "original",
            PatchReverificationCaseKind::OriginalAttack,
            PatchEmpiricalOutcome::Exploited,
        ),
        (
            "control",
            PatchReverificationCaseKind::BenignControl,
            PatchEmpiricalOutcome::CleanExit,
        ),
        (
            "variant-1",
            PatchReverificationCaseKind::Variant,
            PatchEmpiricalOutcome::Exploited,
        ),
    ] {
        for (target, outcome) in [
            (PatchReverificationTarget::Vulnerable, vulnerable_outcome),
            (
                PatchReverificationTarget::Patched,
                PatchEmpiricalOutcome::CleanExit,
            ),
        ] {
            steps.push(PatchReverificationStep {
                case_id: case_id.to_string(),
                case_kind,
                target,
                input_digest: "b".repeat(64),
                backend: super::PersistedSandboxBackend::Bwrap,
                outcome,
                reached_sink: true,
                passed: true,
            });
        }
    }
    let touched_files = record
        .touched_files
        .iter()
        .map(|file| PatchReverificationFileHash {
            path: file.path.clone(),
            hash: None,
        })
        .collect::<Vec<_>>();
    PatchReverificationReceipt {
        schema_version: PATCH_REVERIFICATION_RECEIPT_SCHEMA_VERSION,
        application_id: record.application_id.clone(),
        patch_run_id: record.patch_run_id.clone(),
        reverify_run_id: record
            .reverify_run_id
            .clone()
            .unwrap_or_else(|| "reverify-1".to_string()),
        source_identity: TargetContentIdentity::IndexedSnapshot {
            snapshot_hash: crate::run_lifecycle::SafeText::operator_visible("c".repeat(64)),
            tree_hash: Some(crate::run_lifecycle::SafeText::operator_visible(
                "d".repeat(64),
            )),
        },
        source_commit: record
            .base_commit
            .clone()
            .unwrap_or_else(|| "source-commit".to_string()),
        diff_hash: record.diff_hash.clone(),
        reproducer,
        steps,
        detector_tool: "semgrep:scan".to_string(),
        detector_run_id: "scan-1".to_string(),
        detector_outcome: PatchDetectorReplayOutcome::NotRediscovered,
        start_touched_files: touched_files.clone(),
        end_touched_files: touched_files,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content_store::ObjectKind;
    use crate::run_lifecycle::SafeText;

    #[test]
    fn complete_receipt_round_trips_through_cas() {
        let temp = tempfile::tempdir().unwrap();
        let store = crate::content_store::ContentStore::open(temp.path()).unwrap();
        let reproducer = store
            .put_json(
                ObjectKind::ProofSnapshot,
                &serde_json::json!({"schemaVersion": 2}),
            )
            .unwrap();
        let receipt = receipt(reproducer);
        receipt.validate_for_verified().unwrap();

        let receipt_ref = store.put_json(ObjectKind::ProofSnapshot, &receipt).unwrap();
        let bytes = store.get_object(&receipt_ref).unwrap();
        let decoded: PatchReverificationReceipt = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(decoded, receipt);
        decoded.validate_for_verified().unwrap();
    }

    #[test]
    fn verified_receipt_rejects_tampered_empirical_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let store = crate::content_store::ContentStore::open(temp.path()).unwrap();
        let reproducer = store
            .put_json(ObjectKind::ProofSnapshot, &serde_json::json!({}))
            .unwrap();
        let valid = receipt(reproducer);

        let mut untrusted = valid.clone();
        untrusted.steps[0].backend = super::super::PersistedSandboxBackend::Podman;
        assert_validation_error(untrusted, "untrusted empirical step");

        let mut unbound = valid.clone();
        unbound.steps[0].input_digest = "a".repeat(64);
        assert_validation_error(unbound, "one bound vulnerable/patched pair");

        let mut changed_files = valid.clone();
        changed_files.end_touched_files[0].hash = Some("f".repeat(64));
        assert_validation_error(changed_files, "hashes changed during reverification");

        let mut wrong_outcome = valid;
        wrong_outcome.steps[0].outcome = PatchEmpiricalOutcome::CleanExit;
        assert_validation_error(wrong_outcome, "attack ladder");
    }

    fn assert_validation_error(receipt: PatchReverificationReceipt, expected: &str) {
        let error = receipt.validate_for_verified().unwrap_err().to_string();
        assert!(error.contains(expected), "{error}");
    }

    fn receipt(reproducer: ObjectRef) -> PatchReverificationReceipt {
        let mut steps = Vec::new();
        for (case_id, case_kind, vulnerable_outcome) in [
            (
                "original",
                PatchReverificationCaseKind::OriginalAttack,
                PatchEmpiricalOutcome::Exploited,
            ),
            (
                "control",
                PatchReverificationCaseKind::BenignControl,
                PatchEmpiricalOutcome::CleanExit,
            ),
            (
                "variant-1",
                PatchReverificationCaseKind::Variant,
                PatchEmpiricalOutcome::Exploited,
            ),
        ] {
            for (target, outcome) in [
                (PatchReverificationTarget::Vulnerable, vulnerable_outcome),
                (
                    PatchReverificationTarget::Patched,
                    PatchEmpiricalOutcome::CleanExit,
                ),
            ] {
                steps.push(PatchReverificationStep {
                    case_id: case_id.to_string(),
                    case_kind,
                    target,
                    input_digest: "b".repeat(64),
                    backend: super::super::PersistedSandboxBackend::Bwrap,
                    outcome,
                    reached_sink: true,
                    passed: true,
                });
            }
        }
        PatchReverificationReceipt {
            schema_version: PATCH_REVERIFICATION_RECEIPT_SCHEMA_VERSION,
            application_id: "application-1".to_string(),
            patch_run_id: "patch-1".to_string(),
            reverify_run_id: "reverify-1".to_string(),
            source_identity: TargetContentIdentity::IndexedSnapshot {
                snapshot_hash: SafeText::operator_visible("c".repeat(64)),
                tree_hash: Some(SafeText::operator_visible("d".repeat(64))),
            },
            source_commit: "source-commit".to_string(),
            diff_hash: "diff-hash".to_string(),
            reproducer,
            steps,
            detector_tool: "semgrep:scan".to_string(),
            detector_run_id: "scan-1".to_string(),
            detector_outcome: PatchDetectorReplayOutcome::NotRediscovered,
            start_touched_files: vec![PatchReverificationFileHash {
                path: "src/lib.rs".to_string(),
                hash: Some("e".repeat(64)),
            }],
            end_touched_files: vec![PatchReverificationFileHash {
                path: "src/lib.rs".to_string(),
                hash: Some("e".repeat(64)),
            }],
        }
    }
}
