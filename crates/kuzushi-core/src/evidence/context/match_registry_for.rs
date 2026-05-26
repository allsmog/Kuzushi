use super::*;

pub(crate) fn match_registry_for(
    language: &str,
    symbol_hint: Option<&str>,
    source_snippet: Option<&str>,
) -> Vec<StaticRegistryMatch> {
    if language == "unknown" {
        return Vec::new();
    }
    let mut query = StaticRegistryQuery::new(language);
    if let Some(symbol) = symbol_hint {
        query = query.symbol(symbol);
    }
    if let Some(text) = source_snippet {
        query = query.text(text);
    }
    match_static_registry(&query)
}

pub(crate) fn derive_narrative(finding: &Finding) -> Option<StaticFindingNarrative> {
    // We pass an empty ranked slice; the narrative builder still produces
    // trigger-path / impact / evidence-limits text based on the finding
    // alone. Rank/score are surfaced separately via `compute_impact_score`.
    let ranked: Vec<StaticRankedFinding> = Vec::new();
    let report = build_static_narrative_report(std::slice::from_ref(finding), &ranked).ok()?;
    report.narratives.into_iter().next()
}

pub(crate) fn load_subgraph_slice(
    finding: &Finding,
    workspace_root: &Path,
) -> (Vec<StaticEvidenceNode>, Vec<StaticEvidenceEdge>) {
    let store = match open_static_evidence_store(workspace_root) {
        Some(store) => store,
        None => return (Vec::new(), Vec::new()),
    };
    let nodes = subgraph_nodes_for_finding(&store, finding);
    let edges = subgraph_edges_for_nodes(&store, &nodes);

    (nodes, edges)
}

fn open_static_evidence_store(workspace_root: &Path) -> Option<StaticEvidenceStore> {
    let store_path = crate::workspace::workspace_static_evidence_db_path(workspace_root);
    if store_path.exists() {
        StaticEvidenceStore::open_path(store_path).ok()
    } else {
        None
    }
}

fn subgraph_nodes_for_finding(
    store: &StaticEvidenceStore,
    finding: &Finding,
) -> Vec<StaticEvidenceNode> {
    let kept_kinds = [
        StaticEvidenceNodeKind::Source,
        StaticEvidenceNodeKind::Sink,
        StaticEvidenceNodeKind::Sanitizer,
        StaticEvidenceNodeKind::Guard,
        StaticEvidenceNodeKind::CodeSpan,
    ];
    let mut nodes: Vec<StaticEvidenceNode> = store
        .list_nodes_for_finding(&finding.fingerprint)
        .unwrap_or_default()
        .into_iter()
        .filter(|node| kept_kinds.contains(&node.kind))
        .filter(|node| node_within_window(node, finding.start_line, &finding.file_path))
        .take(SUBGRAPH_NODE_CAP)
        .collect();

    // Stable order: by start_line then by id, so the prompt is deterministic.
    nodes.sort_by(|a, b| {
        a.start_line
            .unwrap_or(0)
            .cmp(&b.start_line.unwrap_or(0))
            .then_with(|| a.id.cmp(&b.id))
    });

    nodes
}

fn subgraph_edges_for_nodes(
    store: &StaticEvidenceStore,
    nodes: &[StaticEvidenceNode],
) -> Vec<StaticEvidenceEdge> {
    let kept_ids: std::collections::HashSet<&str> = nodes.iter().map(|n| n.id.as_str()).collect();
    let mut edges: Vec<StaticEvidenceEdge> = nodes
        .iter()
        .flat_map(|node| store.edges_for_node(&node.id).unwrap_or_default())
        .filter(|edge| {
            kept_ids.contains(edge.from_node_id.as_str())
                && kept_ids.contains(edge.to_node_id.as_str())
        })
        .collect();
    edges.sort_by(|a, b| a.id.cmp(&b.id));
    edges.dedup_by(|a, b| a.id == b.id);
    edges
}

pub(crate) fn node_within_window(
    node: &StaticEvidenceNode,
    finding_line: u32,
    finding_file: &str,
) -> bool {
    // Different file -> out of window.
    if let Some(path) = &node.source_path {
        if path != finding_file && !finding_file.ends_with(path) && !path.ends_with(finding_file) {
            return false;
        }
    }
    let line = node.start_line.unwrap_or(finding_line);
    line.abs_diff(finding_line) <= SUBGRAPH_LINE_WINDOW
}

pub(crate) fn compute_impact_score(
    finding: &Finding,
) -> Option<crate::static_ranking::StaticImpactScore> {
    let ranked = rank_static_findings(std::slice::from_ref(finding), None, None).ok()?;
    ranked.into_iter().next().map(|r| r.impact)
}
