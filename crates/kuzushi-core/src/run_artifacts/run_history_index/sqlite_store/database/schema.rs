use anyhow::Result;
use rusqlite::Connection;

pub(super) const INDEX_SCHEMA_VERSION: i64 = 3;
const MAX_SCHEMA_SQL_BYTES: i64 = 8 * 1024;
const META_TABLE_SQL: &str = "CREATE TABLE run_history_meta (
             singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
             schema_version INTEGER NOT NULL,
             runs_present INTEGER NOT NULL,
             runs_secs INTEGER NOT NULL,
             runs_nanos INTEGER NOT NULL,
             canonical_total INTEGER NOT NULL CHECK (canonical_total >= 0),
             retained_count INTEGER NOT NULL CHECK (retained_count >= 0),
             retained_bytes INTEGER NOT NULL CHECK (retained_bytes >= 0),
             retention_max_rows INTEGER NOT NULL CHECK (retention_max_rows > 0),
             retention_max_bytes INTEGER NOT NULL CHECK (retention_max_bytes > 0),
             oldest_state_rank INTEGER,
             oldest_started_at_unix INTEGER,
             oldest_ready_run_id TEXT,
             oldest_issue_run_id TEXT,
             truncated INTEGER NOT NULL CHECK (truncated IN (0, 1)),
             generation INTEGER NOT NULL CHECK (generation > 0),
             canonical_xor BLOB NOT NULL CHECK (length(canonical_xor) = 32),
             canonical_digest TEXT NOT NULL,
             table_digest TEXT NOT NULL
         )";
const ENTRIES_TABLE_SQL: &str = "CREATE TABLE run_history_entries (
             run_id TEXT PRIMARY KEY,
             state_rank INTEGER NOT NULL CHECK (state_rank IN (0, 1)),
             started_at_unix INTEGER NOT NULL CHECK (started_at_unix >= 0),
             ready_run_id TEXT NOT NULL,
             issue_run_id TEXT NOT NULL,
             issue_json TEXT,
             entry_bytes INTEGER NOT NULL CHECK (entry_bytes > 0),
             CHECK (
                 (state_rank = 0 AND issue_json IS NULL AND
                  ready_run_id = run_id AND issue_run_id = '') OR
                 (state_rank = 1 AND issue_json IS NOT NULL AND
                  started_at_unix = 0 AND ready_run_id = '' AND
                  issue_run_id = run_id)
             )
         ) WITHOUT ROWID";
const ORDER_INDEX_SQL: &str = "CREATE INDEX run_history_canonical_order ON run_history_entries (
             state_rank ASC, started_at_unix DESC,
             ready_run_id DESC, issue_run_id ASC
         )";

type SchemaObject = (String, String, String, Option<String>);

pub(super) fn initialize_schema(connection: &Connection) -> Result<()> {
    connection.execute_batch(&format!(
        "{META_TABLE_SQL};{ENTRIES_TABLE_SQL};{ORDER_INDEX_SQL};"
    ))?;
    Ok(())
}

pub(super) fn validate_schema(connection: &Connection) -> Result<()> {
    let version: i64 = connection.query_row(
        "SELECT schema_version FROM run_history_meta WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    anyhow::ensure!(
        version == INDEX_SCHEMA_VERSION,
        "run-history index schema is unsupported"
    );
    validate_schema_objects(connection)
}

fn validate_schema_objects(connection: &Connection) -> Result<()> {
    let mut statement = connection.prepare_cached(
        "SELECT type, name, tbl_name,
                CASE WHEN length(sql) <= ?1 THEN sql ELSE NULL END
         FROM sqlite_schema
         WHERE name NOT LIKE 'sqlite_%'
         LIMIT 4",
    )?;
    let rows = statement.query_map([MAX_SCHEMA_SQL_BYTES], read_schema_object)?;
    let mut objects = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    objects.sort_by(|left, right| left.1.cmp(&right.1));
    anyhow::ensure!(
        objects == expected_schema_objects(),
        "run-history index schema objects are invalid"
    );
    Ok(())
}

fn read_schema_object(row: &rusqlite::Row<'_>) -> rusqlite::Result<SchemaObject> {
    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
}

fn expected_schema_objects() -> Vec<SchemaObject> {
    [
        (
            "index",
            "run_history_canonical_order",
            "run_history_entries",
        ),
        ("table", "run_history_entries", "run_history_entries"),
        ("table", "run_history_meta", "run_history_meta"),
    ]
    .into_iter()
    .map(expected_schema_object)
    .collect()
}

fn expected_schema_object(value: (&str, &str, &str)) -> SchemaObject {
    let (kind, name, table) = value;
    (
        kind.to_string(),
        name.to_string(),
        table.to_string(),
        Some(expected_schema_sql(name).to_string()),
    )
}

fn expected_schema_sql(name: &str) -> &'static str {
    match name {
        "run_history_meta" => META_TABLE_SQL,
        "run_history_entries" => ENTRIES_TABLE_SQL,
        "run_history_canonical_order" => ORDER_INDEX_SQL,
        _ => "",
    }
}
