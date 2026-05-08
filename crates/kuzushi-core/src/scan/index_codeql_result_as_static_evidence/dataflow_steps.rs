use super::*;

pub(super) fn index_codeql_dataflow_steps(
    store: &StaticEvidenceStore,
    repo_root: &Path,
    finding: &Finding,
    finding_fingerprint: &str,
    scanner_signal_id: &str,
    flow_steps: &[CodeqlFlowStep],
    indexed: &mut CodeqlStaticEvidenceIndex,
) -> Result<()> {
    let mut previous_step_id: Option<String> = None;
    for (sequence, step) in flow_steps.iter().enumerate() {
        let span = crate::source_span::extract_source_span(
            repo_root,
            &step.file_path,
            step.line,
            step.line,
        )?;
        let step_node = StaticEvidenceNode::new(
            StaticEvidenceNodeKind::DataflowStep,
            format!(
                "CodeQL dataflow step {} for {} at {}:{}",
                sequence + 1,
                finding.rule_id,
                span.file_path,
                span.start_line
            ),
            span.snippet.clone(),
        )
        .with_finding_fingerprint(finding_fingerprint.to_string())
        .with_source_span(span.file_path.clone(), span.start_line, Some(span.end_line))
        .with_metadata(json!({
            "normalizer": "codeql",
            "tool": "codeql",
            "ruleId": finding.rule_id.as_str(),
            "sequence": sequence + 1,
            "message": step.message.as_deref(),
            "sarifSnippet": step.snippet.as_deref(),
            "sourceContentHash": span.content_hash.as_str(),
        }));

        store.upsert_node(&step_node)?;
        indexed.nodes_indexed += 1;
        indexed.node_ids.push(step_node.id.clone());

        index_signal_step_edge(
            store,
            finding_fingerprint,
            scanner_signal_id,
            &step_node,
            sequence,
            indexed,
        )?;
        index_adjacent_flow_edge(
            store,
            finding_fingerprint,
            previous_step_id,
            &step_node,
            sequence,
            indexed,
        )?;
        previous_step_id = Some(step_node.id);
    }
    Ok(())
}

fn index_signal_step_edge(
    store: &StaticEvidenceStore,
    finding_fingerprint: &str,
    scanner_signal_id: &str,
    step_node: &StaticEvidenceNode,
    sequence: usize,
    indexed: &mut CodeqlStaticEvidenceIndex,
) -> Result<()> {
    let signal_to_step = StaticEvidenceEdge::new(
        StaticEvidenceEdgeKind::DerivedFrom,
        scanner_signal_id.to_string(),
        step_node.id.clone(),
    )
    .with_finding_fingerprint(finding_fingerprint.to_string())
    .with_metadata(json!({
        "normalizer": "codeql",
        "relationship": "scanner_signal_to_dataflow_step",
        "sequence": sequence + 1,
    }));
    store.upsert_edge(&signal_to_step)?;
    indexed.edges_indexed += 1;
    indexed.edge_ids.push(signal_to_step.id);
    Ok(())
}

fn index_adjacent_flow_edge(
    store: &StaticEvidenceStore,
    finding_fingerprint: &str,
    previous_step_id: Option<String>,
    step_node: &StaticEvidenceNode,
    sequence: usize,
    indexed: &mut CodeqlStaticEvidenceIndex,
) -> Result<()> {
    let Some(previous_step_id) = previous_step_id else {
        return Ok(());
    };
    let flow_edge = StaticEvidenceEdge::new(
        StaticEvidenceEdgeKind::FlowsTo,
        previous_step_id,
        step_node.id.clone(),
    )
    .with_finding_fingerprint(finding_fingerprint.to_string())
    .with_metadata(json!({
        "normalizer": "codeql",
        "relationship": "adjacent_codeql_flow_location",
        "toSequence": sequence + 1,
    }));
    store.upsert_edge(&flow_edge)?;
    indexed.edges_indexed += 1;
    indexed.edge_ids.push(flow_edge.id);
    Ok(())
}
