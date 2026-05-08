use super::*;

pub(crate) fn validate_node(node: &StaticEvidenceNode) -> Result<()> {
    if node.id.trim().is_empty() {
        anyhow::bail!("static evidence node id cannot be empty");
    }
    if node.id != node.stable_id() {
        anyhow::bail!(
            "static evidence node id {} does not match stable hash {}",
            node.id,
            node.stable_id()
        );
    }
    let expected_hash = static_content_hash(&node.body);
    if node.content_hash != expected_hash {
        anyhow::bail!(
            "static evidence node {} content hash does not match body hash",
            node.id
        );
    }
    validate_node_line_range(node)
}

fn validate_node_line_range(node: &StaticEvidenceNode) -> Result<()> {
    if let Some(start_line) = node.start_line {
        if start_line == 0 {
            anyhow::bail!("static evidence node {} start_line must be >= 1", node.id);
        }
    }
    if let (Some(start_line), Some(end_line)) = (node.start_line, node.end_line) {
        if end_line < start_line {
            anyhow::bail!(
                "static evidence node {} end_line must be >= start_line",
                node.id
            );
        }
    }
    Ok(())
}

pub(crate) fn validate_edge(edge: &StaticEvidenceEdge) -> Result<()> {
    if edge.from_node_id.trim().is_empty() || edge.to_node_id.trim().is_empty() {
        anyhow::bail!("static evidence edge endpoints cannot be empty");
    }
    if edge.id != edge.stable_id() {
        anyhow::bail!(
            "static evidence edge id {} does not match stable hash {}",
            edge.id,
            edge.stable_id()
        );
    }
    Ok(())
}
