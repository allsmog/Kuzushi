use super::{FindingIdentityAuditReport, IDENTITY_AUDIT_EVIDENCE_SCHEMA_VERSION};
use crate::findings::{Finding, ReviewDecisionRecord};
use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AuditDigestPayload<'a> {
    pub(super) schema_version: u32,
    pub(super) canonical_target_key: &'a str,
    pub(super) corpus_watermark: &'a str,
    pub(super) report: &'a FindingIdentityAuditReport,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CorpusWatermarkPayload<'a> {
    findings: Vec<&'a Finding>,
    decisions: Vec<&'a ReviewDecisionRecord>,
}

pub(super) fn corpus_watermark(
    findings: &[Finding],
    decisions: &[ReviewDecisionRecord],
) -> Result<String> {
    let mut findings = findings.iter().collect::<Vec<_>>();
    findings.sort_by_key(|finding| (finding.id, finding.fingerprint.as_str()));
    let mut decisions = decisions.iter().collect::<Vec<_>>();
    decisions.sort_by_key(|decision| (decision.id, decision.finding_id));
    sha256_json(&CorpusWatermarkPayload {
        findings,
        decisions,
    })
}

pub(super) fn canonical_target_key(target: &Path) -> Result<String> {
    fs::canonicalize(target)
        .with_context(|| {
            format!(
                "could not canonicalize identity-audit target {}",
                target.display()
            )
        })
        .map(|path| path.display().to_string())
}

pub(super) fn sha256_json(value: &impl Serialize) -> Result<String> {
    Ok(format!(
        "sha256:{}",
        sha256_bytes(&serde_json::to_vec(value)?)
    ))
}

pub(super) fn sha256_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) fn audit_digest_payload<'a>(
    canonical_target_key: &'a str,
    corpus_watermark: &'a str,
    report: &'a FindingIdentityAuditReport,
) -> AuditDigestPayload<'a> {
    AuditDigestPayload {
        schema_version: IDENTITY_AUDIT_EVIDENCE_SCHEMA_VERSION,
        canonical_target_key,
        corpus_watermark,
        report,
    }
}
