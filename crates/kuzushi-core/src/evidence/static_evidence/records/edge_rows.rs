use super::*;

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
