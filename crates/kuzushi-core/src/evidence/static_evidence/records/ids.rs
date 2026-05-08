use super::*;

pub(crate) fn evidence_node_id(node: &StaticEvidenceNode) -> String {
    let metadata_json = serde_json::to_string(&node.metadata).unwrap_or_else(|_| "{}".to_string());
    let hash = stable_hash_segments(&[
        "node",
        node.kind.as_str(),
        node.finding_fingerprint.as_deref().unwrap_or(""),
        node.source_path.as_deref().unwrap_or(""),
        &node
            .start_line
            .map(|line| line.to_string())
            .unwrap_or_default(),
        &node
            .end_line
            .map(|line| line.to_string())
            .unwrap_or_default(),
        &node.content_hash,
        &node.title,
        &metadata_json,
    ]);
    format!("SEV-N-{}", &hash[..16])
}
