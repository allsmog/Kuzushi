use super::*;

pub fn validate_whitebox_suppression(record: &WhiteboxSuppressionRecord) -> Result<()> {
    validate_suppression_scope(record)?;
    validate_suppression_evidence(record)?;
    validate_suppression_metadata(record)?;
    if record.id != stable_whitebox_suppression_id(record) {
        anyhow::bail!(
            "whitebox suppression id {} does not match stable scope/evidence hash",
            record.id
        );
    }
    Ok(())
}

fn validate_suppression_scope(record: &WhiteboxSuppressionRecord) -> Result<()> {
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
    Ok(())
}

fn validate_suppression_evidence(record: &WhiteboxSuppressionRecord) -> Result<()> {
    if record.evidence.is_empty() {
        anyhow::bail!("whitebox suppression requires evidence");
    }
    for evidence in &record.evidence {
        if !suppression_evidence_is_valid(evidence) {
            anyhow::bail!(
                "whitebox suppression evidence requires filePath, valid lines, snippetHash, and description"
            );
        }
    }
    Ok(())
}

fn suppression_evidence_is_valid(evidence: &WhiteboxSuppressionEvidence) -> bool {
    !evidence.file_path.trim().is_empty()
        && evidence.start_line != 0
        && evidence.end_line >= evidence.start_line
        && !evidence.snippet_hash.trim().is_empty()
        && !evidence.description.trim().is_empty()
}

fn validate_suppression_metadata(record: &WhiteboxSuppressionRecord) -> Result<()> {
    if record.reason.trim().is_empty() {
        anyhow::bail!("whitebox suppression reason is required");
    }
    if record.author.trim().is_empty() {
        anyhow::bail!("whitebox suppression author is required");
    }
    if record.expires_at_unix <= record.created_at_unix {
        anyhow::bail!("whitebox suppression expiration must be after creation time");
    }
    Ok(())
}

pub(crate) fn suppression_matches_finding(
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

pub(crate) fn stable_whitebox_suppression_id(record: &WhiteboxSuppressionRecord) -> String {
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

pub(crate) fn sorted_suppressions(
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

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
