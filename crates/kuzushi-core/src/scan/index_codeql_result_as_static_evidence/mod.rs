use super::*;

mod dataflow_steps;

pub(crate) fn index_codeql_result_as_static_evidence(
    store: &StaticEvidenceStore,
    repo_root: &Path,
    finding: &Finding,
    result: &CodeqlSarifResult,
) -> Result<CodeqlStaticEvidenceIndex> {
    let mut indexed = CodeqlStaticEvidenceIndex::default();
    let finding_fingerprint = finding.fingerprint.clone();
    let end_line = finding.end_line.unwrap_or(finding.start_line);
    let primary_span = crate::source_span::extract_source_span(
        repo_root,
        &finding.file_path,
        finding.start_line,
        end_line,
    )?;
    let location = format!(
        "{}:{}-{}",
        primary_span.file_path, primary_span.start_line, primary_span.end_line
    );
    let flow_steps = extract_codeql_flow_steps(result);
    let static_proof_state = finding
        .static_proof_state
        .unwrap_or(StaticProofState::SignalOnly)
        .as_str();

    let code_span = StaticEvidenceNode::new(
        StaticEvidenceNodeKind::CodeSpan,
        format!("CodeQL code span {} at {location}", finding.rule_id),
        primary_span.snippet.clone(),
    )
    .with_finding_fingerprint(finding_fingerprint.clone())
    .with_source_span(
        primary_span.file_path.clone(),
        primary_span.start_line,
        Some(primary_span.end_line),
    )
    .with_metadata(json!({
        "normalizer": "codeql",
        "tool": "codeql",
        "ruleId": finding.rule_id.as_str(),
        "severity": finding.severity.as_str(),
        "sourceContentHash": primary_span.content_hash.as_str(),
    }));

    let scanner_signal = StaticEvidenceNode::new(
        StaticEvidenceNodeKind::ScannerSignal,
        format!("CodeQL signal {} at {location}", finding.rule_id),
        format!(
            "CodeQL rule {} reported {} with severity {}.\n\n{}",
            finding.rule_id,
            location,
            finding.severity.as_str(),
            finding.message.as_str()
        ),
    )
    .with_finding_fingerprint(finding_fingerprint.clone())
    .with_source_span(
        primary_span.file_path.clone(),
        primary_span.start_line,
        Some(primary_span.end_line),
    )
    .with_metadata(json!({
        "normalizer": "codeql",
        "tool": "codeql",
        "ruleId": finding.rule_id.as_str(),
        "severity": finding.severity.as_str(),
        "staticProofState": static_proof_state,
        "truePositiveByDefault": false,
        "defaultVerdict": "untriaged_signal",
        "codeFlowStepCount": flow_steps.len(),
        "sourceContentHash": primary_span.content_hash.as_str(),
    }));

    let signal_to_span = StaticEvidenceEdge::new(
        StaticEvidenceEdgeKind::DerivedFrom,
        scanner_signal.id.clone(),
        code_span.id.clone(),
    )
    .with_finding_fingerprint(finding_fingerprint.clone())
    .with_metadata(json!({
        "normalizer": "codeql",
        "relationship": "scanner_signal_to_primary_code_span",
        "truePositiveByDefault": false,
    }));

    store.upsert_node(&code_span)?;
    indexed.nodes_indexed += 1;
    indexed.node_ids.push(code_span.id.clone());
    store.upsert_node(&scanner_signal)?;
    indexed.nodes_indexed += 1;
    indexed.node_ids.push(scanner_signal.id.clone());
    store.upsert_edge(&signal_to_span)?;
    indexed.edges_indexed += 1;
    indexed.edge_ids.push(signal_to_span.id);

    dataflow_steps::index_codeql_dataflow_steps(
        store,
        repo_root,
        finding,
        &finding_fingerprint,
        &scanner_signal.id,
        &flow_steps,
        &mut indexed,
    )?;

    Ok(indexed)
}
