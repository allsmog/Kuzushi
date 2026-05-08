use super::prelude::*;
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

pub(crate) fn row_to_node(row: &rusqlite::Row<'_>) -> rusqlite::Result<StaticEvidenceNode> {
    let raw_kind: String = row.get(1)?;
    let metadata_json: String = row.get(9)?;
    let metadata = serde_json::from_str::<Value>(&metadata_json).map_err(to_sql_error)?;
    let start_line = optional_u32(row.get::<_, Option<i64>>(4)?, "start_line")?;
    let end_line = optional_u32(row.get::<_, Option<i64>>(5)?, "end_line")?;
    Ok(StaticEvidenceNode {
        id: row.get(0)?,
        kind: StaticEvidenceNodeKind::try_from(raw_kind.as_str()).map_err(to_sql_anyhow_error)?,
        finding_fingerprint: row.get(2)?,
        source_path: row.get(3)?,
        start_line,
        end_line,
        content_hash: row.get(6)?,
        title: row.get(7)?,
        body: row.get(8)?,
        metadata,
        indexed_at_unix: row.get::<_, i64>(10)? as u64,
    })
}

pub(crate) fn row_to_edge(row: &rusqlite::Row<'_>) -> rusqlite::Result<StaticEvidenceEdge> {
    let raw_kind: String = row.get(1)?;
    let metadata_json: String = row.get(5)?;
    let metadata = serde_json::from_str::<Value>(&metadata_json).map_err(to_sql_error)?;
    Ok(StaticEvidenceEdge {
        id: row.get(0)?,
        kind: StaticEvidenceEdgeKind::try_from(raw_kind.as_str()).map_err(to_sql_anyhow_error)?,
        from_node_id: row.get(2)?,
        to_node_id: row.get(3)?,
        finding_fingerprint: row.get(4)?,
        metadata,
        created_at_unix: row.get::<_, i64>(6)? as u64,
    })
}

pub(crate) fn optional_u32(
    value: Option<i64>,
    name: &'static str,
) -> rusqlite::Result<Option<u32>> {
    match value {
        Some(value) if value < 0 || value > i64::from(u32::MAX) => Err(to_sql_anyhow_error(
            anyhow::anyhow!("static evidence {name} value {value} is out of range"),
        )),
        Some(value) => Ok(Some(value as u32)),
        None => Ok(None),
    }
}

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
