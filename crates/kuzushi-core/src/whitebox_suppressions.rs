use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::findings::Finding;
use crate::source_span::extract_source_span;
use crate::static_evidence::static_content_hash;
use crate::workspace::WorkspaceTarget;

const WHITEBOX_SUPPRESSION_STORE_NAME: &str = "whitebox-suppressions.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WhiteboxSuppressionScope {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding_fingerprint: Option<String>,
    pub rule_id: String,
    pub file_path: String,
    pub start_line: u32,
    pub end_line: u32,
    pub snippet_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WhiteboxSuppressionEvidence {
    pub file_path: String,
    pub start_line: u32,
    pub end_line: u32,
    pub snippet_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WhiteboxSuppressionRecord {
    pub id: String,
    pub scope: WhiteboxSuppressionScope,
    pub evidence: Vec<WhiteboxSuppressionEvidence>,
    pub reason: String,
    pub author: String,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WhiteboxSuppressionMatch {
    pub finding_fingerprint: String,
    pub suppression_id: String,
    pub reason: String,
    pub author: String,
    pub expires_at_unix: u64,
    pub file_path: String,
    pub start_line: u32,
    pub end_line: u32,
    pub snippet_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WhiteboxStaleSuppression {
    pub suppression_id: String,
    pub file_path: String,
    pub start_line: u32,
    pub end_line: u32,
    pub expected_snippet_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_snippet_hash: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WhiteboxExpiredSuppression {
    pub suppression_id: String,
    pub expired_at_unix: u64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WhiteboxSuppressionReport {
    pub total_suppressions: usize,
    pub active_suppressions: usize,
    pub suppressed_count: usize,
    pub suppressed_findings: Vec<WhiteboxSuppressionMatch>,
    pub stale_suppressions: Vec<WhiteboxStaleSuppression>,
    pub expired_suppressions: Vec<WhiteboxExpiredSuppression>,
    pub findings_remain_visible: bool,
    pub audit_note: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WhiteboxSuppressionStoreFile {
    version: u8,
    suppressions: Vec<WhiteboxSuppressionRecord>,
}

impl Default for WhiteboxSuppressionStoreFile {
    fn default() -> Self {
        Self {
            version: 1,
            suppressions: Vec::new(),
        }
    }
}

pub fn whitebox_suppression_store_path(workspace: &WorkspaceTarget) -> PathBuf {
    workspace.state_dir().join(WHITEBOX_SUPPRESSION_STORE_NAME)
}

pub fn load_whitebox_suppressions(
    workspace: &WorkspaceTarget,
) -> Result<Vec<WhiteboxSuppressionRecord>> {
    let path = whitebox_suppression_store_path(workspace);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let body =
        fs::read_to_string(&path).with_context(|| format!("Could not read {}", path.display()))?;
    let value: Value = serde_json::from_str(&body)
        .with_context(|| format!("Could not parse {}", path.display()))?;
    let suppressions = if value.is_array() {
        serde_json::from_value(value)
            .with_context(|| format!("Could not parse {}", path.display()))?
    } else {
        serde_json::from_value::<WhiteboxSuppressionStoreFile>(value)
            .with_context(|| format!("Could not parse {}", path.display()))?
            .suppressions
    };
    for record in &suppressions {
        validate_whitebox_suppression(record)?;
    }
    Ok(sorted_suppressions(suppressions))
}

pub fn save_whitebox_suppressions(
    workspace: &WorkspaceTarget,
    suppressions: &[WhiteboxSuppressionRecord],
) -> Result<()> {
    workspace.ensure_state_dir()?;
    for record in suppressions {
        validate_whitebox_suppression(record)?;
    }
    let path = whitebox_suppression_store_path(workspace);
    let store = WhiteboxSuppressionStoreFile {
        version: 1,
        suppressions: sorted_suppressions(suppressions.to_vec()),
    };
    let body = format!("{}\n", serde_json::to_string_pretty(&store)?);
    fs::write(&path, body).with_context(|| format!("Could not write {}", path.display()))
}

pub fn upsert_whitebox_suppression(
    workspace: &WorkspaceTarget,
    record: WhiteboxSuppressionRecord,
) -> Result<WhiteboxSuppressionRecord> {
    validate_whitebox_suppression(&record)?;
    let mut suppressions = load_whitebox_suppressions(workspace)?;
    if let Some(existing) = suppressions
        .iter_mut()
        .find(|existing| existing.id == record.id)
    {
        *existing = record.clone();
    } else {
        suppressions.push(record.clone());
    }
    save_whitebox_suppressions(workspace, &suppressions)?;
    Ok(record)
}

pub fn build_whitebox_suppression_for_finding(
    repo_root: impl AsRef<Path>,
    finding: &Finding,
    reason: impl Into<String>,
    author: impl Into<String>,
    expires_at_unix: u64,
) -> Result<WhiteboxSuppressionRecord> {
    let created_at_unix = now_unix();
    build_whitebox_suppression_for_finding_at(
        repo_root,
        finding,
        reason,
        author,
        created_at_unix,
        expires_at_unix,
    )
}

pub fn build_whitebox_suppression_for_finding_at(
    repo_root: impl AsRef<Path>,
    finding: &Finding,
    reason: impl Into<String>,
    author: impl Into<String>,
    created_at_unix: u64,
    expires_at_unix: u64,
) -> Result<WhiteboxSuppressionRecord> {
    let end_line = finding.end_line.unwrap_or(finding.start_line);
    let span = extract_source_span(repo_root, &finding.file_path, finding.start_line, end_line)?;
    let scope = WhiteboxSuppressionScope {
        finding_fingerprint: Some(finding.fingerprint.clone()),
        rule_id: finding.rule_id.clone(),
        file_path: span.file_path.clone(),
        start_line: span.start_line,
        end_line: span.end_line,
        snippet_hash: span.content_hash.clone(),
    };
    let evidence = WhiteboxSuppressionEvidence {
        file_path: span.file_path.clone(),
        start_line: span.start_line,
        end_line: span.end_line,
        snippet_hash: span.content_hash,
        snippet: Some(span.snippet),
        description: format!(
            "Operator-reviewed source span for {} at {}:{}-{}",
            finding.rule_id, span.file_path, span.start_line, span.end_line
        ),
    };
    let reason = reason.into();
    let author = author.into();
    let mut record = WhiteboxSuppressionRecord {
        id: String::new(),
        scope,
        evidence: vec![evidence],
        reason,
        author,
        created_at_unix,
        expires_at_unix,
        metadata: json!({
            "findingTitle": finding.title.as_str(),
            "findingTool": finding.tool.as_str(),
            "staticProofState": finding
                .static_proof_state
                .map(|state| state.as_str()),
        }),
    };
    record.id = stable_whitebox_suppression_id(&record);
    validate_whitebox_suppression(&record)?;
    Ok(record)
}

pub fn evaluate_whitebox_suppressions(
    repo_root: impl AsRef<Path>,
    findings: &[Finding],
    suppressions: &[WhiteboxSuppressionRecord],
    now_unix: u64,
) -> WhiteboxSuppressionReport {
    let repo_root = repo_root.as_ref();
    let mut report = WhiteboxSuppressionReport {
        total_suppressions: suppressions.len(),
        active_suppressions: 0,
        suppressed_count: 0,
        suppressed_findings: Vec::new(),
        stale_suppressions: Vec::new(),
        expired_suppressions: Vec::new(),
        findings_remain_visible: true,
        audit_note:
            "whitebox-static suppressions annotate false-positive memory; audit/report output still includes suppressed findings"
                .to_string(),
    };

    for suppression in suppressions {
        if suppression.expires_at_unix <= now_unix {
            report
                .expired_suppressions
                .push(WhiteboxExpiredSuppression {
                    suppression_id: suppression.id.clone(),
                    expired_at_unix: suppression.expires_at_unix,
                    reason: suppression.reason.clone(),
                });
            continue;
        }

        report.active_suppressions += 1;
        let current_span = extract_source_span(
            repo_root,
            &suppression.scope.file_path,
            suppression.scope.start_line,
            suppression.scope.end_line,
        );
        let Ok(current_span) = current_span else {
            report.stale_suppressions.push(WhiteboxStaleSuppression {
                suppression_id: suppression.id.clone(),
                file_path: suppression.scope.file_path.clone(),
                start_line: suppression.scope.start_line,
                end_line: suppression.scope.end_line,
                expected_snippet_hash: suppression.scope.snippet_hash.clone(),
                current_snippet_hash: None,
                reason: "suppressed source span no longer resolves under the repository"
                    .to_string(),
            });
            continue;
        };
        if current_span.content_hash != suppression.scope.snippet_hash {
            report.stale_suppressions.push(WhiteboxStaleSuppression {
                suppression_id: suppression.id.clone(),
                file_path: suppression.scope.file_path.clone(),
                start_line: suppression.scope.start_line,
                end_line: suppression.scope.end_line,
                expected_snippet_hash: suppression.scope.snippet_hash.clone(),
                current_snippet_hash: Some(current_span.content_hash),
                reason: "suppressed source snippet hash changed".to_string(),
            });
            continue;
        }

        for finding in findings {
            if !suppression_matches_finding(suppression, finding, &current_span.content_hash) {
                continue;
            }
            report.suppressed_findings.push(WhiteboxSuppressionMatch {
                finding_fingerprint: finding.fingerprint.clone(),
                suppression_id: suppression.id.clone(),
                reason: suppression.reason.clone(),
                author: suppression.author.clone(),
                expires_at_unix: suppression.expires_at_unix,
                file_path: suppression.scope.file_path.clone(),
                start_line: suppression.scope.start_line,
                end_line: suppression.scope.end_line,
                snippet_hash: suppression.scope.snippet_hash.clone(),
            });
        }
    }

    report.suppressed_findings.sort_by(|left, right| {
        left.finding_fingerprint
            .cmp(&right.finding_fingerprint)
            .then_with(|| left.suppression_id.cmp(&right.suppression_id))
    });
    report.suppressed_findings.dedup();
    report.suppressed_count = report.suppressed_findings.len();
    report
}

pub fn findings_visible_with_whitebox_suppressions(findings: &[Finding]) -> Vec<Finding> {
    findings.to_vec()
}

pub fn validate_whitebox_suppression(record: &WhiteboxSuppressionRecord) -> Result<()> {
    if record.id.trim().is_empty() {
        anyhow::bail!("whitebox suppression id is required");
    }
    if record.scope.rule_id.trim().is_empty() {
        anyhow::bail!("whitebox suppression scope ruleId is required");
    }
    if record.scope.file_path.trim().is_empty() {
        anyhow::bail!("whitebox suppression scope filePath is required");
    }
    if record.scope.start_line == 0 || record.scope.end_line == 0 {
        anyhow::bail!("whitebox suppression scope line numbers must be 1-based");
    }
    if record.scope.end_line < record.scope.start_line {
        anyhow::bail!("whitebox suppression scope endLine must be >= startLine");
    }
    if record.scope.snippet_hash.trim().is_empty() {
        anyhow::bail!("whitebox suppression scope snippetHash is required");
    }
    if record.evidence.is_empty() {
        anyhow::bail!("whitebox suppression requires evidence");
    }
    for evidence in &record.evidence {
        if evidence.file_path.trim().is_empty()
            || evidence.start_line == 0
            || evidence.end_line < evidence.start_line
            || evidence.snippet_hash.trim().is_empty()
            || evidence.description.trim().is_empty()
        {
            anyhow::bail!(
                "whitebox suppression evidence requires filePath, valid lines, snippetHash, and description"
            );
        }
    }
    if record.reason.trim().is_empty() {
        anyhow::bail!("whitebox suppression reason is required");
    }
    if record.author.trim().is_empty() {
        anyhow::bail!("whitebox suppression author is required");
    }
    if record.expires_at_unix <= record.created_at_unix {
        anyhow::bail!("whitebox suppression expiration must be after creation time");
    }
    if record.id != stable_whitebox_suppression_id(record) {
        anyhow::bail!(
            "whitebox suppression id {} does not match stable scope/evidence hash",
            record.id
        );
    }
    Ok(())
}

fn suppression_matches_finding(
    suppression: &WhiteboxSuppressionRecord,
    finding: &Finding,
    current_snippet_hash: &str,
) -> bool {
    let end_line = finding.end_line.unwrap_or(finding.start_line);
    suppression.scope.rule_id == finding.rule_id
        && suppression.scope.file_path == finding.file_path
        && suppression.scope.start_line == finding.start_line
        && suppression.scope.end_line == end_line
        && suppression.scope.snippet_hash == current_snippet_hash
}

fn stable_whitebox_suppression_id(record: &WhiteboxSuppressionRecord) -> String {
    let metadata_json =
        serde_json::to_string(&record.metadata).unwrap_or_else(|_| "{}".to_string());
    let evidence_json = serde_json::to_string(&record.evidence).unwrap_or_default();
    let body = [
        "whitebox-suppression",
        record.scope.finding_fingerprint.as_deref().unwrap_or(""),
        record.scope.rule_id.as_str(),
        record.scope.file_path.as_str(),
        &record.scope.start_line.to_string(),
        &record.scope.end_line.to_string(),
        record.scope.snippet_hash.as_str(),
        record.reason.as_str(),
        record.author.as_str(),
        &record.created_at_unix.to_string(),
        &record.expires_at_unix.to_string(),
        &evidence_json,
        &metadata_json,
    ]
    .join("\0");
    format!("WBSUP-{}", static_content_hash(&body))
}

fn sorted_suppressions(
    mut suppressions: Vec<WhiteboxSuppressionRecord>,
) -> Vec<WhiteboxSuppressionRecord> {
    suppressions.sort_by(|left, right| {
        left.scope
            .file_path
            .cmp(&right.scope.file_path)
            .then_with(|| left.scope.start_line.cmp(&right.scope.start_line))
            .then_with(|| left.id.cmp(&right.id))
    });
    suppressions
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::findings::{Severity, StaticProofState};

    fn finding() -> Finding {
        Finding::new_tool(
            "semgrep",
            "javascript.express.xss",
            "src/server.js",
            2,
            Some(2),
            Severity::High,
            "query data reaches html response",
        )
        .with_static_proof_state(StaticProofState::StaticallyRejected)
    }

    fn write_fixture(root: &Path, line: &str) {
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("src/server.js"),
            format!("const express = require('express');\n{line}\n"),
        )
        .unwrap();
    }

    #[test]
    fn whitebox_suppression_requires_evidence_reason_author_and_expiration() {
        let temp = tempfile::tempdir().unwrap();
        write_fixture(temp.path(), "res.send(escapeHtml(req.query.name));");
        let finding = finding();
        let mut record = build_whitebox_suppression_for_finding_at(
            temp.path(),
            &finding,
            "escaped before response",
            "security@example.test",
            10,
            20,
        )
        .unwrap();

        record.reason.clear();
        assert!(validate_whitebox_suppression(&record)
            .unwrap_err()
            .to_string()
            .contains("reason"));

        record.reason = "escaped before response".to_string();
        record.author.clear();
        assert!(validate_whitebox_suppression(&record)
            .unwrap_err()
            .to_string()
            .contains("author"));

        record.author = "security@example.test".to_string();
        record.evidence.clear();
        assert!(validate_whitebox_suppression(&record)
            .unwrap_err()
            .to_string()
            .contains("requires evidence"));

        record.evidence.push(WhiteboxSuppressionEvidence {
            file_path: "src/server.js".to_string(),
            start_line: 2,
            end_line: 2,
            snippet_hash: record.scope.snippet_hash.clone(),
            snippet: None,
            description: "reviewed sanitizer".to_string(),
        });
        record.expires_at_unix = record.created_at_unix;
        assert!(validate_whitebox_suppression(&record)
            .unwrap_err()
            .to_string()
            .contains("expiration"));
    }

    #[test]
    fn whitebox_suppression_round_trips_under_v2_state() {
        let temp = tempfile::tempdir().unwrap();
        write_fixture(temp.path(), "res.send(escapeHtml(req.query.name));");
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let finding = finding();
        let record = build_whitebox_suppression_for_finding_at(
            workspace.root(),
            &finding,
            "escaped before response",
            "security@example.test",
            100,
            200,
        )
        .unwrap();

        upsert_whitebox_suppression(&workspace, record.clone()).unwrap();
        let loaded = load_whitebox_suppressions(&workspace).unwrap();

        assert_eq!(
            whitebox_suppression_store_path(&workspace),
            workspace.state_dir().join("whitebox-suppressions.json")
        );
        assert_eq!(loaded, vec![record]);
    }

    #[test]
    fn whitebox_suppression_matches_until_snippet_hash_changes() {
        let temp = tempfile::tempdir().unwrap();
        write_fixture(temp.path(), "res.send(escapeHtml(req.query.name));");
        let finding = finding();
        let record = build_whitebox_suppression_for_finding_at(
            temp.path(),
            &finding,
            "escaped before response",
            "security@example.test",
            100,
            200,
        )
        .unwrap();

        let report =
            evaluate_whitebox_suppressions(temp.path(), &[finding.clone()], &[record.clone()], 150);
        assert_eq!(report.suppressed_count, 1);
        assert!(report.stale_suppressions.is_empty());
        assert!(report.findings_remain_visible);

        write_fixture(temp.path(), "res.send(req.query.name);");
        let report = evaluate_whitebox_suppressions(temp.path(), &[finding], &[record], 150);
        assert_eq!(report.suppressed_count, 0);
        assert_eq!(report.stale_suppressions.len(), 1);
        assert_eq!(
            report.stale_suppressions[0].reason,
            "suppressed source snippet hash changed"
        );
    }

    #[test]
    fn whitebox_suppression_expiration_prevents_match() {
        let temp = tempfile::tempdir().unwrap();
        write_fixture(temp.path(), "res.send(escapeHtml(req.query.name));");
        let finding = finding();
        let record = build_whitebox_suppression_for_finding_at(
            temp.path(),
            &finding,
            "escaped before response",
            "security@example.test",
            100,
            120,
        )
        .unwrap();

        let report = evaluate_whitebox_suppressions(temp.path(), &[finding], &[record], 121);

        assert_eq!(report.suppressed_count, 0);
        assert_eq!(report.expired_suppressions.len(), 1);
        assert_eq!(report.active_suppressions, 0);
    }

    #[test]
    fn suppressed_findings_remain_visible_for_audit_and_report_mode() {
        let temp = tempfile::tempdir().unwrap();
        write_fixture(temp.path(), "res.send(escapeHtml(req.query.name));");
        let finding = finding();
        let record = build_whitebox_suppression_for_finding_at(
            temp.path(),
            &finding,
            "escaped before response",
            "security@example.test",
            100,
            200,
        )
        .unwrap();

        let report =
            evaluate_whitebox_suppressions(temp.path(), &[finding.clone()], &[record], 150);
        let visible = findings_visible_with_whitebox_suppressions(&[finding.clone()]);

        assert_eq!(report.suppressed_count, 1);
        assert!(report
            .audit_note
            .contains("still includes suppressed findings"));
        assert_eq!(visible, vec![finding]);
    }
}
