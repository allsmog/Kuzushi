use super::*;

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
