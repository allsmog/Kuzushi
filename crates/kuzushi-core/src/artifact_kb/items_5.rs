use super::prelude::*;
use super::*;

pub(crate) fn infer_title(source_path: &str, absolute: &Path) -> String {
    if source_path.ends_with("summary.json") {
        if let Some(run_id) = infer_run_id(source_path) {
            return format!("run {run_id} summary");
        }
    }
    absolute
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(source_path)
        .to_string()
}

pub(crate) fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<ArtifactKnowledgeRecord> {
    let refs_json: String = row.get(8)?;
    let metadata_json: String = row.get(9)?;
    let refs = serde_json::from_str::<Vec<String>>(&refs_json).map_err(to_sql_error)?;
    let metadata = serde_json::from_str::<Value>(&metadata_json).map_err(to_sql_error)?;
    Ok(ArtifactKnowledgeRecord {
        id: row.get(0)?,
        source_path: row.get(1)?,
        module_id: row.get(2)?,
        run_id: row.get(3)?,
        content_hash: row.get(4)?,
        title: row.get(5)?,
        summary: row.get(6)?,
        body: row.get(7)?,
        refs,
        metadata,
        indexed_at_unix: row.get::<_, i64>(10)? as u64,
    })
}

pub(crate) fn sqlite_table_exists(conn: &Connection, table: &str) -> Result<bool> {
    conn.query_row(
        "select 1 from sqlite_master where type = 'table' and name = ?1 limit 1",
        params![table],
        |_| Ok(()),
    )
    .optional()
    .map(|value| value.is_some())
    .context("Could not inspect SQLite schema")
}

pub(crate) fn to_sql_error(error: serde_json::Error) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
}

pub(crate) fn build_fts_query(query: &str) -> Option<String> {
    let tokens = query
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_' && ch != '-')
        .map(str::trim)
        .filter(|token| token.len() >= 2)
        .map(|token| token.replace('"', ""))
        .collect::<Vec<_>>();
    if tokens.is_empty() {
        None
    } else {
        Some(
            tokens
                .into_iter()
                .map(|token| format!("\"{token}\"*"))
                .collect::<Vec<_>>()
                .join(" OR "),
        )
    }
}

pub(crate) fn summarize_body(body: &str) -> String {
    body.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("")
        .chars()
        .take(240)
        .collect()
}

pub(crate) fn compact_prompt_text(text: &str, max_chars: usize) -> String {
    let mut compact = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if compact.chars().count() > max_chars {
        compact = compact.chars().take(max_chars).collect::<String>();
        compact.push_str("...");
    }
    compact
}

pub(crate) fn artifact_record_id(
    module_id: &str,
    source_path: &str,
    run_id: Option<&str>,
    title: &str,
) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(module_id.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(source_path.as_bytes());
    bytes.push(0);
    if let Some(run_id) = run_id {
        bytes.extend_from_slice(run_id.as_bytes());
    }
    bytes.push(0);
    bytes.extend_from_slice(title.as_bytes());
    let hash = fnv1a_hex(&bytes);
    format!("KB-{}", &hash[..12])
}
