use super::{
    disposition_error, FindingIdentityAuditApprovalReceipt, FindingIdentityAuditEvidence,
    IdentityPolicyApprovalStatus, IDENTITY_AUDIT_APPROVAL_DIR,
    IDENTITY_AUDIT_APPROVAL_SCHEMA_VERSION,
};
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub fn identity_audit_approval_receipt_path(
    operator_state_dir: &Path,
    canonical_target_key: &str,
) -> PathBuf {
    operator_state_dir
        .join(IDENTITY_AUDIT_APPROVAL_DIR)
        .join(format!(
            "sha256-{}.json",
            super::canonical::sha256_bytes(canonical_target_key.as_bytes())
        ))
}

pub(super) fn approval_status(
    operator_state_dir: &Path,
    evidence: &FindingIdentityAuditEvidence,
) -> IdentityPolicyApprovalStatus {
    let path =
        identity_audit_approval_receipt_path(operator_state_dir, &evidence.canonical_target_key);
    let Some(receipt) = load_receipt(&path) else {
        return missing_or_malformed(&path);
    };
    validate_receipt(&receipt, evidence)
}

fn missing_or_malformed(path: &Path) -> IdentityPolicyApprovalStatus {
    if path.exists() {
        IdentityPolicyApprovalStatus::Malformed
    } else {
        IdentityPolicyApprovalStatus::Missing
    }
}

fn validate_receipt(
    receipt: &FindingIdentityAuditApprovalReceipt,
    evidence: &FindingIdentityAuditEvidence,
) -> IdentityPolicyApprovalStatus {
    receipt_schema_or_target_error(receipt, evidence)
        .or_else(|| receipt_digest_error(receipt, evidence))
        .or_else(|| receipt_review_error(receipt, evidence))
        .unwrap_or(IdentityPolicyApprovalStatus::Approved)
}

fn receipt_schema_or_target_error(
    receipt: &FindingIdentityAuditApprovalReceipt,
    evidence: &FindingIdentityAuditEvidence,
) -> Option<IdentityPolicyApprovalStatus> {
    (receipt.schema_version != IDENTITY_AUDIT_APPROVAL_SCHEMA_VERSION)
        .then_some(IdentityPolicyApprovalStatus::Malformed)
        .or_else(|| {
            (receipt.canonical_target_key != evidence.canonical_target_key)
                .then_some(IdentityPolicyApprovalStatus::WrongTarget)
        })
}

fn receipt_digest_error(
    receipt: &FindingIdentityAuditApprovalReceipt,
    evidence: &FindingIdentityAuditEvidence,
) -> Option<IdentityPolicyApprovalStatus> {
    (receipt.corpus_watermark != evidence.corpus_watermark)
        .then_some(IdentityPolicyApprovalStatus::StaleCorpus)
        .or_else(|| {
            (receipt.report_sha256 != evidence.report_sha256)
                .then_some(IdentityPolicyApprovalStatus::StaleReport)
        })
}

fn receipt_review_error(
    receipt: &FindingIdentityAuditApprovalReceipt,
    evidence: &FindingIdentityAuditEvidence,
) -> Option<IdentityPolicyApprovalStatus> {
    (receipt.actor.trim().is_empty()
        || disposition_error(&receipt.dispositions, evidence).is_some())
    .then_some(IdentityPolicyApprovalStatus::UnresolvedGroups)
}

fn load_receipt(path: &Path) -> Option<FindingIdentityAuditApprovalReceipt> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_file() || metadata.len() > 1024 * 1024 {
        return None;
    }
    serde_json::from_slice(&fs::read(path).ok()?).ok()
}

pub(super) fn persist_approval_receipt(
    operator_state_dir: &Path,
    receipt: &FindingIdentityAuditApprovalReceipt,
) -> Result<()> {
    let path =
        identity_audit_approval_receipt_path(operator_state_dir, &receipt.canonical_target_key);
    let mut body = serde_json::to_string_pretty(receipt)?;
    body.push('\n');
    crate::fs_atomic::write_atomic(&path, &body).with_context(|| {
        format!(
            "could not persist identity-audit approval at {}",
            path.display()
        )
    })
}
