use super::*;

pub(super) fn push_evidence_graph(
    out: &mut String,
    nodes: &[StaticEvidenceNode],
    edges: &[StaticEvidenceEdge],
) {
    if nodes.is_empty() {
        return;
    }
    out.push_str(&format!(
        "**Evidence graph slice** ({} nodes, +/-{} lines of finding):\n",
        nodes.len(),
        SUBGRAPH_LINE_WINDOW
    ));
    for node in nodes {
        push_evidence_node(out, node);
    }
    if !edges.is_empty() {
        out.push_str("\n");
        for edge in edges {
            push_evidence_edge(out, edge);
        }
    }
    out.push_str("\n");
}

fn push_evidence_node(out: &mut String, node: &StaticEvidenceNode) {
    out.push_str("- ");
    out.push_str(node.kind.as_str());
    if let (Some(path), Some(line)) = (&node.source_path, node.start_line) {
        out.push_str(&format!(" @ `{}:{}`", path, line));
    }
    if !node.body.is_empty() {
        let trimmed = node.body.lines().next().unwrap_or("").trim();
        if !trimmed.is_empty() {
            out.push_str(" body: `");
            out.push_str(&truncate_for_prompt(trimmed, 80));
            out.push_str("`");
        }
    }
    out.push_str("\n");
}

fn push_evidence_edge(out: &mut String, edge: &StaticEvidenceEdge) {
    out.push_str(&format!(
        "- Edge: `{}` --{}--> `{}`\n",
        edge.from_node_id,
        edge.kind.as_str(),
        edge.to_node_id
    ));
}
