use super::contract::{TraceExpansionResult, TraceStep, TRACE_EXPANSION_CONTRACT_VERSION};
use crate::static_evidence::{
    StaticEvidenceEdge, StaticEvidenceEdgeKind, StaticEvidenceNode, StaticEvidenceNodeKind,
    StaticEvidenceStore,
};
use anyhow::Result;
use serde_json::json;

/// Provenance marker on every node/edge this capability appends: the Trace
/// screen distinguishes operator-requested hops from scanner-indexed ones.
pub const OPERATOR_TRACE_PROVENANCE: &str = "requested by operator";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEvidenceReceipt {
    pub node_ids: Vec<String>,
    pub edge_ids: Vec<String>,
}

/// Append the expansion's steps as `DataflowStep` nodes chained by `FlowsTo`
/// edges, all tagged with the finding fingerprint. Ids are content-stable, so
/// re-recording the same expansion is idempotent — the store only ever grows.
pub fn append_trace_expansion_evidence(
    store: &StaticEvidenceStore,
    result: &TraceExpansionResult,
) -> Result<TraceEvidenceReceipt> {
    let mut receipt = TraceEvidenceReceipt {
        node_ids: Vec::new(),
        edge_ids: Vec::new(),
    };
    for (index, step) in result.steps.iter().enumerate() {
        let node = trace_step_node(&result.finding_fingerprint, index, step);
        store.upsert_node(&node)?;
        if let Some(previous_id) = receipt.node_ids.last() {
            let edge = StaticEvidenceEdge::new(StaticEvidenceEdgeKind::FlowsTo, previous_id, &node.id)
                .with_finding_fingerprint(&result.finding_fingerprint)
                .with_metadata(json!({ "provenance": OPERATOR_TRACE_PROVENANCE }));
            store.upsert_edge(&edge)?;
            receipt.edge_ids.push(edge.id);
        }
        receipt.node_ids.push(node.id);
    }
    Ok(receipt)
}

/// Read back the operator-requested hops for a finding, in recorded step
/// order per expansion batch. This is the durable source the Trace screen
/// renders from — not the tool-result snapshot.
pub fn list_operator_trace_steps(
    store: &StaticEvidenceStore,
    fingerprint: &str,
) -> Result<Vec<TraceStep>> {
    let mut ordered: Vec<(u64, u64, TraceStep)> = store
        .list_nodes_for_finding(fingerprint)?
        .into_iter()
        .filter(|node| node.kind == StaticEvidenceNodeKind::DataflowStep)
        .filter_map(|node| {
            let provenance = node.metadata.get("provenance")?.as_str()?;
            (provenance == OPERATOR_TRACE_PROVENANCE).then(|| {
                let step_index = node
                    .metadata
                    .get("stepIndex")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                (
                    node.indexed_at_unix,
                    step_index,
                    TraceStep {
                        symbol: node.title.clone(),
                        file_path: node.source_path.clone().unwrap_or_default(),
                        line: node.start_line.unwrap_or(0),
                        annotation: node.body.clone(),
                    },
                )
            })
        })
        .collect();
    ordered.sort_by_key(|(indexed_at, step_index, _)| (*indexed_at, *step_index));
    Ok(ordered.into_iter().map(|(_, _, step)| step).collect())
}

fn trace_step_node(fingerprint: &str, index: usize, step: &TraceStep) -> StaticEvidenceNode {
    StaticEvidenceNode::new(
        StaticEvidenceNodeKind::DataflowStep,
        step.symbol.clone(),
        step.annotation.clone(),
    )
    .with_finding_fingerprint(fingerprint)
    .with_source_span(step.file_path.clone(), step.line, None)
    .with_metadata(json!({
        "provenance": OPERATOR_TRACE_PROVENANCE,
        "traceExpansionVersion": TRACE_EXPANSION_CONTRACT_VERSION,
        "stepIndex": index,
        "symbol": step.symbol,
    }))
}
