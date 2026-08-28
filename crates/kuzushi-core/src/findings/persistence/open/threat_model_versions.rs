use super::*;
use serde_json::Value;

/// One row of the append-only threat-model version ledger. Summaries never
/// carry the document body — readers fetch it by id when they need it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreatModelVersionRecord {
    pub id: i64,
    pub created_at: String,
    pub source: String,
    pub run_id: Option<String>,
    pub model_id: Option<String>,
    pub revision_id: Option<String>,
    pub methodology: String,
    pub threat_count: u64,
    pub sha256: String,
}

const MAX_LEDGER_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy)]
struct ThreatModelLedgerRef<'a> {
    model_id: &'a str,
    revision_id: &'a str,
}

impl<'a> ThreatModelLedgerRef<'a> {
    fn new(model_id: &'a str, revision_id: &'a str) -> Result<Self> {
        anyhow::ensure!(
            !model_id.trim().is_empty(),
            "threat-model ledger model id is empty"
        );
        anyhow::ensure!(
            !revision_id.trim().is_empty(),
            "threat-model ledger revision id is empty"
        );
        Ok(Self {
            model_id,
            revision_id,
        })
    }
}

/// Canonical content hash for a threat-model document: compact JSON
/// serialization (serde_json maps are order-stable), same `sha256:` prefix
/// convention as prompt content hashes.
/// Content identity of a threat-model document. The `verification` block is
/// excluded: it carries a timestamp and re-verifying an unchanged document
/// must neither defeat ledger sha-dedupe nor un-badge the live version row.
pub fn threat_model_document_sha256(document: &Value) -> String {
    crate::options::prompt_content_sha256(&verification_agnostic_body(document))
}

fn verification_agnostic_body(document: &Value) -> String {
    match document {
        Value::Object(map) if map.contains_key("verification") => {
            let mut map = map.clone();
            map.remove("verification");
            Value::Object(map).to_string()
        }
        other => other.to_string(),
    }
}

impl FindingStore {
    /// Append a version row unless the document is byte-identical to the
    /// latest ledger entry (repeated saves of an unchanged model stay one
    /// row). Returns the new row id, or None when deduplicated.
    pub fn record_threat_model_version(
        &self,
        document: &Value,
        source: &str,
        run_id: Option<&str>,
    ) -> Result<Option<i64>> {
        self.record_threat_model_version_entry(document, source, run_id, None)
    }

    /// Append a ledger row bound to one immutable model revision. Unlike the
    /// compatibility API, equal document content under a different revision
    /// is a distinct event and must remain traceable.
    pub fn record_threat_model_version_with_ref(
        &self,
        document: &Value,
        source: &str,
        run_id: Option<&str>,
        model_id: &str,
        revision_id: &str,
    ) -> Result<Option<i64>> {
        let model_ref = ThreatModelLedgerRef::new(model_id, revision_id)?;
        self.record_threat_model_version_entry(document, source, run_id, Some(model_ref))
    }

    fn record_threat_model_version_entry(
        &self,
        document: &Value,
        source: &str,
        run_id: Option<&str>,
        model_ref: Option<ThreatModelLedgerRef<'_>>,
    ) -> Result<Option<i64>> {
        let body = document.to_string();
        anyhow::ensure!(
            body.len() <= MAX_LEDGER_DOCUMENT_BYTES,
            "threat model document exceeds the {MAX_LEDGER_DOCUMENT_BYTES} byte ledger limit"
        );
        let sha256 = threat_model_document_sha256(document);
        if self.latest_threat_model_version_matches(&sha256, model_ref)? {
            return Ok(None);
        }
        self.insert_threat_model_version(document, source, run_id, model_ref, &sha256, body)
            .map(Some)
    }

    fn insert_threat_model_version(
        &self,
        document: &Value,
        source: &str,
        run_id: Option<&str>,
        model_ref: Option<ThreatModelLedgerRef<'_>>,
        sha256: &str,
        body: String,
    ) -> Result<i64> {
        self.conn
            .execute(
                "insert into threat_model_versions
                   (created_at, source, run_id, model_id, revision_id, methodology,
                    threat_count, sha256, document_json)
                 values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    now_isoish(),
                    source,
                    run_id,
                    model_ref.map(|model_ref| model_ref.model_id),
                    model_ref.map(|model_ref| model_ref.revision_id),
                    document_methodology(document),
                    document_threat_count(document),
                    sha256,
                    body,
                ],
            )
            .context("Could not append threat-model version")?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Newest-first version summaries. Empty (not an error) when the ledger
    /// table does not exist yet — read-only opens of pre-ledger databases.
    pub fn list_threat_model_versions(
        &self,
        limit: usize,
    ) -> Result<Vec<ThreatModelVersionRecord>> {
        let query = format!(
            "select {} from threat_model_versions order by id desc limit ?1",
            self.threat_model_version_summary_columns()?
        );
        let mut stmt = match self.conn.prepare(&query) {
            Ok(stmt) => stmt,
            Err(error) if is_missing_ledger_table(&error) => return Ok(Vec::new()),
            Err(error) => {
                return Err(error).context("Could not query threat-model versions");
            }
        };
        let rows = stmt.query_map(params![limit as i64], threat_model_version_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not load threat-model versions")
    }

    pub fn threat_model_version_summary(
        &self,
        id: i64,
    ) -> Result<Option<ThreatModelVersionRecord>> {
        let query = format!(
            "select {} from threat_model_versions where id = ?1",
            self.threat_model_version_summary_columns()?
        );
        self.conn
            .query_row(&query, params![id], threat_model_version_row)
            .optional()
            .context("Could not load threat-model version summary")
    }

    pub fn threat_model_version_document(&self, id: i64) -> Result<Option<Value>> {
        let body: Option<String> = self
            .conn
            .query_row(
                "select document_json from threat_model_versions where id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()
            .context("Could not load threat-model version document")?;
        body.map(|body| {
            serde_json::from_str(&body)
                .with_context(|| format!("Threat-model version {id} is malformed"))
        })
        .transpose()
    }

    fn latest_threat_model_version_matches(
        &self,
        sha256: &str,
        model_ref: Option<ThreatModelLedgerRef<'_>>,
    ) -> Result<bool> {
        let latest = self
            .conn
            .query_row(
                "select sha256, model_id, revision_id
                   from threat_model_versions order by id desc limit 1",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .context("Could not read latest threat-model version identity")?;
        Ok(latest.is_some_and(|latest| latest_version_matches(latest, sha256, model_ref)))
    }

    fn threat_model_version_summary_columns(&self) -> Result<&'static str> {
        if ledger_has_ref_columns(&self.conn)? {
            return Ok("id, created_at, source, run_id, methodology, threat_count, sha256, model_id, revision_id");
        }
        Ok("id, created_at, source, run_id, methodology, threat_count, sha256, null, null")
    }
}

fn latest_version_matches(
    latest: (String, Option<String>, Option<String>),
    sha256: &str,
    model_ref: Option<ThreatModelLedgerRef<'_>>,
) -> bool {
    if latest.0 != sha256 {
        return false;
    }
    model_ref.is_none_or(|model_ref| {
        latest.1.as_deref() == Some(model_ref.model_id)
            && latest.2.as_deref() == Some(model_ref.revision_id)
    })
}

fn ledger_has_ref_columns(conn: &Connection) -> Result<bool> {
    let mut stmt = conn.prepare("pragma table_info(threat_model_versions)")?;
    let columns = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<std::collections::BTreeSet<_>>>()?;
    Ok(columns.contains("model_id") && columns.contains("revision_id"))
}

fn is_missing_ledger_table(error: &rusqlite::Error) -> bool {
    error
        .to_string()
        .contains("no such table: threat_model_versions")
}

fn threat_model_version_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ThreatModelVersionRecord> {
    Ok(ThreatModelVersionRecord {
        id: row.get(0)?,
        created_at: row.get(1)?,
        source: row.get(2)?,
        run_id: row.get(3)?,
        methodology: row.get(4)?,
        threat_count: row.get::<_, i64>(5)?.max(0) as u64,
        sha256: row.get(6)?,
        model_id: row.get(7)?,
        revision_id: row.get(8)?,
    })
}

fn document_methodology(document: &Value) -> String {
    document
        .get("methodology")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string()
}

fn document_threat_count(document: &Value) -> i64 {
    document
        .pointer("/threats")
        .and_then(Value::as_array)
        .map(|threats| threats.len() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_document(title: &str) -> Value {
        json!({
            "methodology": "stride",
            "threats": [{"id": "T-001", "title": title}],
        })
    }

    #[test]
    fn record_appends_and_dedupes_identical_documents() {
        let store = FindingStore::open_in_memory().unwrap();
        let document = sample_document("first");

        let first = store
            .record_threat_model_version(&document, "build", Some("run-1"))
            .unwrap();
        let duplicate = store
            .record_threat_model_version(&document, "build", Some("run-2"))
            .unwrap();
        let changed = store
            .record_threat_model_version(&sample_document("second"), "build", None)
            .unwrap();

        assert!(first.is_some());
        assert!(duplicate.is_none(), "identical re-save must not add a row");
        assert!(changed.is_some());
        let versions = store.list_threat_model_versions(10).unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].threat_count, 1);
        assert_eq!(versions[0].methodology, "stride");
        assert_eq!(versions[1].run_id.as_deref(), Some("run-1"));
    }

    #[test]
    fn version_document_round_trips_and_hash_matches() {
        let store = FindingStore::open_in_memory().unwrap();
        let document = sample_document("round-trip");
        let id = store
            .record_threat_model_version(&document, "build", None)
            .unwrap()
            .unwrap();

        let loaded = store.threat_model_version_document(id).unwrap().unwrap();
        let versions = store.list_threat_model_versions(10).unwrap();

        assert_eq!(loaded, document);
        assert_eq!(versions[0].sha256, threat_model_document_sha256(&document));
        assert!(store.threat_model_version_document(9999).unwrap().is_none());
    }

    #[test]
    fn immutable_refs_round_trip_and_only_dedupe_the_same_revision() {
        let store = FindingStore::open_in_memory().unwrap();
        let document = sample_document("revisioned");

        let first = store
            .record_threat_model_version_with_ref(
                &document,
                "build",
                Some("run-1"),
                "tm_lineage",
                "tmr_first",
            )
            .unwrap();
        let retry = store
            .record_threat_model_version_with_ref(
                &document,
                "build",
                Some("run-1"),
                "tm_lineage",
                "tmr_first",
            )
            .unwrap();
        let next_revision = store
            .record_threat_model_version_with_ref(
                &document,
                "restore",
                None,
                "tm_lineage",
                "tmr_second",
            )
            .unwrap();

        assert!(first.is_some());
        assert!(retry.is_none());
        assert!(next_revision.is_some());
        let versions = store.list_threat_model_versions(10).unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].model_id.as_deref(), Some("tm_lineage"));
        assert_eq!(versions[0].revision_id.as_deref(), Some("tmr_second"));
        assert_eq!(versions[1].revision_id.as_deref(), Some("tmr_first"));
    }

    #[test]
    fn read_only_legacy_ledger_projects_null_refs_without_migrating() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("legacy.sqlite3");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            r#"
            pragma user_version = 1;
            create table threat_model_versions (
              id integer primary key autoincrement, created_at text not null,
              source text not null, run_id text, methodology text not null,
              threat_count integer not null, sha256 text not null,
              document_json text not null
            );
            insert into threat_model_versions values
              (1, '1000', 'build', 'run-old', 'stride', 1, 'sha256:old', '{}');
            "#,
        )
        .unwrap();
        drop(conn);

        let store = FindingStore::open_read_only(&path).unwrap();
        let versions = store.list_threat_model_versions(10).unwrap();

        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].model_id, None);
        assert_eq!(versions[0].revision_id, None);
        assert!(!ledger_has_ref_columns(&store.conn).unwrap());
    }

    #[test]
    fn reselecting_an_older_document_appends_a_new_row() {
        let store = FindingStore::open_in_memory().unwrap();
        let original = sample_document("original");
        store
            .record_threat_model_version(&original, "build", None)
            .unwrap();
        store
            .record_threat_model_version(&sample_document("newer"), "build", None)
            .unwrap();

        let restored = store
            .record_threat_model_version(&original, "restore", None)
            .unwrap();

        assert!(
            restored.is_some(),
            "restore of a non-latest doc is a new row"
        );
        assert_eq!(store.list_threat_model_versions(10).unwrap().len(), 3);
    }
}
