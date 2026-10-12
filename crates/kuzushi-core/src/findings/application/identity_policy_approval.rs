//! Operator-owned approval gate for basis-aware finding identity defaults.

use super::{audit_finding_identities, FindingIdentityAuditReport};
use crate::findings::{Finding, FindingStore, ReviewDecisionRecord};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

mod approval_store;
mod canonical;
pub use approval_store::identity_audit_approval_receipt_path;
use approval_store::{approval_status, persist_approval_receipt};
use canonical::{audit_digest_payload, canonical_target_key, corpus_watermark, sha256_json};

pub const IDENTITY_AUDIT_EVIDENCE_SCHEMA_VERSION: u32 = 1;
pub const IDENTITY_AUDIT_APPROVAL_SCHEMA_VERSION: u32 = 1;
pub const IDENTITY_AUDIT_APPROVAL_DIR: &str = "identity-audit-approvals";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingIdentityAuditEvidence {
    pub schema_version: u32,
    pub canonical_target_key: String,
    pub corpus_watermark: String,
    pub report_sha256: String,
    pub report: FindingIdentityAuditReport,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingIdentityAuditDisposition {
    Accepted,
    Fixed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingIdentityAuditGroupDisposition {
    pub identity_id: String,
    pub disposition: FindingIdentityAuditDisposition,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingIdentityAuditApprovalRequest {
    pub schema_version: u32,
    pub canonical_target_key: String,
    pub corpus_watermark: String,
    pub report_sha256: String,
    pub actor: String,
    pub dispositions: Vec<FindingIdentityAuditGroupDisposition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingIdentityAuditApprovalReceipt {
    pub schema_version: u32,
    pub canonical_target_key: String,
    pub corpus_watermark: String,
    pub report_sha256: String,
    pub approved_at: String,
    pub actor: String,
    pub dispositions: Vec<FindingIdentityAuditGroupDisposition>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentityPolicyApprovalStatus {
    Approved,
    Missing,
    Malformed,
    WrongTarget,
    StaleCorpus,
    StaleReport,
    UnresolvedGroups,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IdentityPolicyDefaults {
    pub identity_fold: String,
    pub identity_reconcile: String,
    pub approval_status: IdentityPolicyApprovalStatus,
    pub identity_fold_explicit: bool,
    pub identity_reconcile_explicit: bool,
}

pub fn build_finding_identity_audit_evidence(
    target: &Path,
    findings: &[Finding],
    decisions: &[ReviewDecisionRecord],
) -> Result<FindingIdentityAuditEvidence> {
    let canonical_target_key = canonical_target_key(target)?;
    let corpus_watermark = corpus_watermark(findings, decisions)?;
    let report = audit_finding_identities(findings, decisions);
    let payload = audit_digest_payload(&canonical_target_key, &corpus_watermark, &report);
    let report_sha256 = sha256_json(&payload)?;
    Ok(FindingIdentityAuditEvidence {
        schema_version: IDENTITY_AUDIT_EVIDENCE_SCHEMA_VERSION,
        canonical_target_key,
        corpus_watermark,
        report_sha256,
        report,
    })
}

pub fn current_finding_identity_audit_evidence(
    target: &Path,
) -> Result<FindingIdentityAuditEvidence> {
    let workspace = crate::WorkspaceTarget::new(target)?;
    let Some(store) = open_identity_audit_store(&workspace)? else {
        return build_finding_identity_audit_evidence(workspace.root(), &[], &[]);
    };
    let findings = store.list_emitted_finding_generations()?;
    let decisions = store.list_review_decisions_for_findings(&findings)?;
    build_finding_identity_audit_evidence(workspace.root(), &findings, &decisions)
}

fn open_identity_audit_store(workspace: &crate::WorkspaceTarget) -> Result<Option<FindingStore>> {
    let path = workspace.findings_db_path();
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error)
            .with_context(|| format!("could not inspect findings database {}", path.display())),
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            FindingStore::open_read_only(path).map(Some)
        }
        Ok(_) => anyhow::bail!(
            "identity audit findings database must be a regular non-symlink file: {}",
            path.display()
        ),
    }
}

pub fn approve_finding_identity_audit(
    operator_state_dir: &Path,
    target: &Path,
    request: FindingIdentityAuditApprovalRequest,
) -> Result<FindingIdentityAuditApprovalReceipt> {
    let evidence = current_finding_identity_audit_evidence(target)?;
    validate_approval_request(&request, &evidence)?;
    let receipt = FindingIdentityAuditApprovalReceipt {
        schema_version: IDENTITY_AUDIT_APPROVAL_SCHEMA_VERSION,
        canonical_target_key: evidence.canonical_target_key.clone(),
        corpus_watermark: evidence.corpus_watermark,
        report_sha256: evidence.report_sha256,
        approved_at: crate::findings::now_isoish(),
        actor: request.actor.trim().to_string(),
        dispositions: sorted_dispositions(request.dispositions),
    };
    persist_approval_receipt(operator_state_dir, &receipt)?;
    Ok(receipt)
}

/// The fold policy a target's operator-owned identity-policy defaults bind.
///
/// Every operator-facing ledger view projects the corpus through this policy,
/// so a run-scoped reader that picks its own instead reports a different
/// finding total for the same runs on the same screen.
pub fn resolved_identity_fold_policy(
    operator_state_dir: &Path,
    target: &Path,
) -> Result<crate::findings::IdentityFoldPolicy> {
    let defaults = resolve_identity_policy_defaults(operator_state_dir, target, None, None)?;
    crate::findings::IdentityFoldPolicy::parse(Some(&defaults.identity_fold))
}

/// Same policy for readers that hold only the target root and must resolve the
/// operator state directory themselves.
pub fn target_identity_fold_policy(
    target: &Path,
) -> Result<crate::findings::IdentityFoldPolicy> {
    let paths = crate::ConfigPaths::from_target(Some(target))?;
    resolved_identity_fold_policy(&paths.global_state_dir(), target)
}

pub fn resolve_identity_policy_defaults(
    operator_state_dir: &Path,
    target: &Path,
    requested_identity_fold: Option<&str>,
    requested_identity_reconcile: Option<&str>,
) -> Result<IdentityPolicyDefaults> {
    validate_requested_policies(requested_identity_fold, requested_identity_reconcile)?;
    let evidence = current_finding_identity_audit_evidence(target)?;
    let status = approval_status(operator_state_dir, &evidence);
    let approved = status == IdentityPolicyApprovalStatus::Approved;
    Ok(IdentityPolicyDefaults {
        identity_fold: requested_identity_fold
            .unwrap_or(if approved { "safe" } else { "legacy" })
            .to_string(),
        identity_reconcile: requested_identity_reconcile
            .unwrap_or(if approved { "auto" } else { "off" })
            .to_string(),
        approval_status: status,
        identity_fold_explicit: requested_identity_fold.is_some(),
        identity_reconcile_explicit: requested_identity_reconcile.is_some(),
    })
}

fn validate_approval_request(
    request: &FindingIdentityAuditApprovalRequest,
    evidence: &FindingIdentityAuditEvidence,
) -> Result<()> {
    validate_request_header(request)?;
    validate_request_binding(request, evidence)?;
    if let Some(error) = disposition_error(&request.dispositions, evidence) {
        anyhow::bail!(error);
    }
    Ok(())
}

fn validate_request_header(request: &FindingIdentityAuditApprovalRequest) -> Result<()> {
    anyhow::ensure!(
        request.schema_version == IDENTITY_AUDIT_APPROVAL_SCHEMA_VERSION,
        "identity-audit approval schemaVersion must be {}",
        IDENTITY_AUDIT_APPROVAL_SCHEMA_VERSION
    );
    anyhow::ensure!(
        !request.actor.trim().is_empty(),
        "identity-audit approval actor is required"
    );
    Ok(())
}

fn validate_request_binding(
    request: &FindingIdentityAuditApprovalRequest,
    evidence: &FindingIdentityAuditEvidence,
) -> Result<()> {
    anyhow::ensure!(
        request.canonical_target_key == evidence.canonical_target_key,
        "identity-audit approval target does not match the current canonical target"
    );
    anyhow::ensure!(
        request.corpus_watermark == evidence.corpus_watermark,
        "identity-audit approval corpus watermark is stale"
    );
    anyhow::ensure!(
        request.report_sha256 == evidence.report_sha256,
        "identity-audit approval report digest is stale"
    );
    Ok(())
}

fn disposition_error(
    dispositions: &[FindingIdentityAuditGroupDisposition],
    evidence: &FindingIdentityAuditEvidence,
) -> Option<String> {
    let expected = expected_identity_groups(evidence);
    validated_disposition_ids(dispositions, &expected).err()
}

fn expected_identity_groups(evidence: &FindingIdentityAuditEvidence) -> BTreeSet<&str> {
    evidence
        .report
        .suspicious_groups
        .iter()
        .map(|group| group.identity_id.as_str())
        .collect()
}

fn validated_disposition_ids<'a>(
    dispositions: &'a [FindingIdentityAuditGroupDisposition],
    expected: &BTreeSet<&str>,
) -> std::result::Result<BTreeSet<&'a str>, String> {
    let mut provided = BTreeSet::new();
    for disposition in dispositions {
        let identity_id = validate_disposition(disposition, expected)?;
        insert_unique_disposition(&mut provided, identity_id)?;
    }
    require_complete_dispositions(expected, &provided)?;
    Ok(provided)
}

fn validate_disposition<'a>(
    disposition: &'a FindingIdentityAuditGroupDisposition,
    expected: &BTreeSet<&str>,
) -> std::result::Result<&'a str, String> {
    let identity_id = disposition.identity_id.trim();
    if identity_id.is_empty() || disposition.rationale.trim().is_empty() {
        return Err("every suspicious identity group needs a nonempty rationale".to_string());
    }
    if !expected.contains(identity_id) {
        return Err(format!(
            "identity-audit approval names unknown group {identity_id:?}"
        ));
    }
    Ok(identity_id)
}

fn insert_unique_disposition<'a>(
    provided: &mut BTreeSet<&'a str>,
    identity_id: &'a str,
) -> std::result::Result<(), String> {
    if provided.insert(identity_id) {
        Ok(())
    } else {
        Err(format!(
            "identity-audit approval repeats group {identity_id:?}"
        ))
    }
}

fn require_complete_dispositions(
    expected: &BTreeSet<&str>,
    provided: &BTreeSet<&str>,
) -> std::result::Result<(), String> {
    let missing = expected.difference(&provided).copied().collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "identity-audit approval is missing dispositions for {}",
            missing.join(", ")
        ))
    }
}

fn sorted_dispositions(
    mut dispositions: Vec<FindingIdentityAuditGroupDisposition>,
) -> Vec<FindingIdentityAuditGroupDisposition> {
    dispositions.sort_by(|left, right| left.identity_id.cmp(&right.identity_id));
    dispositions
}

fn validate_requested_policies(fold: Option<&str>, reconcile: Option<&str>) -> Result<()> {
    if let Some(value) = fold {
        anyhow::ensure!(
            matches!(value, "legacy" | "safe" | "aggressive"),
            "identityFold must be legacy, safe, or aggressive, got {value:?}"
        );
    }
    if let Some(value) = reconcile {
        anyhow::ensure!(
            matches!(value, "auto" | "off"),
            "identityReconcile must be auto or off, got {value:?}"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;
