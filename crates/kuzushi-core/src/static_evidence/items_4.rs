use super::prelude::*;
use super::*;

pub fn index_semgrep_findings_as_static_evidence(
    store: &StaticEvidenceStore,
    repo_root: impl AsRef<Path>,
    findings: &[Finding],
) -> Result<StaticEvidenceIndexReport> {
    let mut report = StaticEvidenceIndexReport::new(store.db_path());
    let repo_root = repo_root.as_ref();

    for finding in findings.iter().filter(|finding| finding.tool == "semgrep") {
        let end_line = finding.end_line.unwrap_or(finding.start_line);
        let span = extract_source_span(repo_root, &finding.file_path, finding.start_line, end_line)
            .with_context(|| {
                format!(
                    "Could not index Semgrep static evidence for {} at {}:{}-{}",
                    finding.rule_id, finding.file_path, finding.start_line, end_line
                )
            })?;
        let (code_span, scanner_signal, edge) = semgrep_static_evidence_nodes(finding, &span);

        store.upsert_node(&code_span)?;
        store.upsert_node(&scanner_signal)?;
        store.upsert_edge(&edge)?;

        report.findings_indexed += 1;
        report.nodes_indexed += 2;
        report.edges_indexed += 1;
        report.node_ids.push(code_span.id);
        report.node_ids.push(scanner_signal.id);
        report.edge_ids.push(edge.id);
    }

    Ok(report)
}

pub(crate) fn semgrep_static_evidence_nodes(
    finding: &Finding,
    span: &SourceSpan,
) -> (StaticEvidenceNode, StaticEvidenceNode, StaticEvidenceEdge) {
    let finding_fingerprint = finding.fingerprint.clone();
    let location = format!("{}:{}-{}", span.file_path, span.start_line, span.end_line);
    let static_proof_state = finding
        .static_proof_state
        .unwrap_or(StaticProofState::SignalOnly)
        .as_str();

    let code_span = StaticEvidenceNode::new(
        StaticEvidenceNodeKind::CodeSpan,
        format!("Semgrep code span {} at {location}", finding.rule_id),
        span.snippet.clone(),
    )
    .with_finding_fingerprint(finding_fingerprint.clone())
    .with_source_span(span.file_path.clone(), span.start_line, Some(span.end_line))
    .with_metadata(json!({
        "normalizer": "semgrep",
        "tool": "semgrep",
        "ruleId": finding.rule_id.as_str(),
        "severity": finding.severity.as_str(),
        "sourceContentHash": span.content_hash.as_str(),
    }));

    let scanner_signal = StaticEvidenceNode::new(
        StaticEvidenceNodeKind::ScannerSignal,
        format!("Semgrep signal {} at {location}", finding.rule_id),
        format!(
            "Semgrep rule {} reported {} with severity {}.\n\n{}",
            finding.rule_id,
            location,
            finding.severity.as_str(),
            finding.message.as_str()
        ),
    )
    .with_finding_fingerprint(finding_fingerprint.clone())
    .with_source_span(span.file_path.clone(), span.start_line, Some(span.end_line))
    .with_metadata(json!({
        "normalizer": "semgrep",
        "tool": "semgrep",
        "ruleId": finding.rule_id.as_str(),
        "severity": finding.severity.as_str(),
        "staticProofState": static_proof_state,
        "truePositiveByDefault": false,
        "defaultVerdict": "untriaged_signal",
        "sourceContentHash": span.content_hash.as_str(),
    }));

    let edge = StaticEvidenceEdge::new(
        StaticEvidenceEdgeKind::DerivedFrom,
        scanner_signal.id.clone(),
        code_span.id.clone(),
    )
    .with_finding_fingerprint(finding_fingerprint)
    .with_metadata(json!({
        "normalizer": "semgrep",
        "relationship": "scanner_signal_to_code_span",
        "truePositiveByDefault": false,
    }));

    (code_span, scanner_signal, edge)
}
