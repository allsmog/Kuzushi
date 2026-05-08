use super::*;

pub(crate) fn row_to_node(row: &rusqlite::Row<'_>) -> rusqlite::Result<StaticEvidenceNode> {
    let row = static_evidence_node_row(row)?;
    let metadata = serde_json::from_str::<Value>(&row.metadata_json).map_err(to_sql_error)?;
    Ok(StaticEvidenceNode {
        id: row.id,
        kind: StaticEvidenceNodeKind::try_from(row.raw_kind.as_str())
            .map_err(to_sql_anyhow_error)?,
        finding_fingerprint: row.finding_fingerprint,
        source_path: row.source_path,
        start_line: optional_u32(row.start_line, "start_line")?,
        end_line: optional_u32(row.end_line, "end_line")?,
        content_hash: row.content_hash,
        title: row.title,
        body: row.body,
        metadata,
        indexed_at_unix: row.indexed_at_unix as u64,
    })
}

struct StaticEvidenceNodeRow {
    id: String,
    raw_kind: String,
    finding_fingerprint: Option<String>,
    source_path: Option<String>,
    start_line: Option<i64>,
    end_line: Option<i64>,
    content_hash: String,
    title: String,
    body: String,
    metadata_json: String,
    indexed_at_unix: i64,
}

fn static_evidence_node_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StaticEvidenceNodeRow> {
    Ok(StaticEvidenceNodeRow {
        id: row.get(0)?,
        raw_kind: row.get(1)?,
        finding_fingerprint: row.get(2)?,
        source_path: row.get(3)?,
        start_line: row.get(4)?,
        end_line: row.get(5)?,
        content_hash: row.get(6)?,
        title: row.get(7)?,
        body: row.get(8)?,
        metadata_json: row.get(9)?,
        indexed_at_unix: row.get(10)?,
    })
}
