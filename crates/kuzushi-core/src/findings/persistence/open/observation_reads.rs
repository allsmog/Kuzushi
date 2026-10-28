use super::*;
use crate::content_store::ContentStore;
use crate::identity::Blake3Hash;
mod provenance;

/// Pointer to the scanned-time copy of a finding's cited source file:
/// the observation row that stored the file as a content-addressed blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationSourceRef {
    pub blob_hash: String,
    pub display_path: Option<String>,
    pub display_line: Option<i64>,
    pub run_id: String,
}

const LATEST_OBSERVATION_SOURCE_SQL: &str = r#"
select blob_hash, display_path, display_line, run_id
  from finding_observations
 where stable_fp = ?1
   and blob_hash is not null
 order by created_seq desc
 limit 1
"#;

const LATEST_OBSERVATION_SOURCE_FOR_RUN_SQL: &str = r#"
select blob_hash, display_path, display_line, run_id
  from finding_observations
 where stable_fp = ?1
   and run_id = ?2
   and blob_hash is not null
 order by created_seq desc
 limit 1
"#;

/// Which run and source snapshot an observation of one identity came from,
/// and where it sits in the event order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedSnapshot {
    pub created_seq: u64,
    pub run_id: String,
    pub snapshot_hash: String,
}

const OBSERVED_SNAPSHOT_AT_SQL: &str = r#"
select created_seq, run_id, snapshot_hash
  from finding_observations
 where stable_fp = ?1
   and created_seq <= ?2
 order by created_seq desc
 limit 1
"#;

impl FindingStore {
    pub(crate) fn lesson_source_tree_hash(&self, origin: &LessonOrigin) -> Result<Option<String>> {
        self.lesson_observation(origin)?;
        self.conn.query_row(
            "select s.tree_hash from finding_observations o join target_snapshots s on s.snapshot_hash=o.snapshot_hash where o.stable_fp=?1 and o.created_seq=?2 and o.snapshot_hash=?3",
            params![origin.finding.stable_key, i64::try_from(origin.observation_seq)?, origin.snapshot_hash],
            |row| row.get(0),
        ).optional().context("Could not read the lesson's recorded source tree")
    }

    pub(crate) fn lesson_captured_source(
        &self,
        origin: &LessonOrigin,
        limit: usize,
    ) -> Result<serde_json::Value> {
        let captured =
            self.observed_file_identity_at(&origin.finding.stable_key, origin.observation_seq)?;
        let Some((path, hash)) = captured else {
            return Ok(
                serde_json::json!({"status":"not_recorded","omission":"No captured source exists for this exact observation."}),
            );
        };
        let objects = self
            .v3_objects_dir()
            .context("Captured source store is unavailable")?;
        let store = ContentStore::open(objects)?;
        let object = Blake3Hash::new(hash.clone())?;
        let content = if store.object_path(&object).try_exists()? {
            store.get_blob_bounded(&object, limit)?
        } else {
            None
        };
        let text = content
            .map(String::from_utf8)
            .transpose()
            .context("Captured source is not UTF-8 text")?;
        let status = if text.is_some() {
            "included"
        } else {
            "unavailable_or_over_limit"
        };
        Ok(
            serde_json::json!({"status":status,"path":path,"blobHash":hash,"maxBytes":limit,"text":text,"currentSourceRead":false}),
        )
    }

    /// Exact captured file identity at one observation event. A run-specific
    /// snapshot id alone does not establish whether source content changed.
    pub(crate) fn observed_file_identity_at(
        &self,
        stable_fp: &str,
        created_seq: u64,
    ) -> Result<Option<(String, String)>> {
        let seq = i64::try_from(created_seq).unwrap_or(i64::MAX);
        self.conn.query_row(
            "select display_path, blob_hash from finding_observations where stable_fp = ?1 and created_seq = ?2 and display_path is not null and blob_hash is not null limit 1",
            params![stable_fp, seq],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().context("Could not read the captured observation file identity")
    }

    /// Newest observation of `stable_fp` committed at or before `max_seq`.
    /// Pass `u64::MAX` for the latest observation overall.
    pub fn observed_snapshot_at(
        &self,
        stable_fp: &str,
        max_seq: u64,
    ) -> Result<Option<ObservedSnapshot>> {
        let bound = i64::try_from(max_seq).unwrap_or(i64::MAX);
        self.conn
            .query_row(OBSERVED_SNAPSHOT_AT_SQL, params![stable_fp, bound], |row| {
                Ok(ObservedSnapshot {
                    created_seq: u64::try_from(row.get::<_, i64>(0)?).unwrap_or_default(),
                    run_id: row.get(1)?,
                    snapshot_hash: row.get(2)?,
                })
            })
            .optional()
            .context("Could not look up the observed source snapshot")
    }

    /// Latest blob-bearing observation for a finding, preferring the named
    /// run. Merged findings can carry a representative `scan_id` different
    /// from the observation that stored the blob, so a miss on the run-scoped
    /// query falls back to the newest blob for the identity.
    pub fn latest_observation_source(
        &self,
        stable_fp: &str,
        scan_id: Option<&str>,
    ) -> Result<Option<ObservationSourceRef>> {
        if let Some(run_id) = scan_id.filter(|run_id| !run_id.is_empty()) {
            let scoped = self.query_observation_source(
                LATEST_OBSERVATION_SOURCE_FOR_RUN_SQL,
                params![stable_fp, run_id],
            )?;
            if scoped.is_some() {
                return Ok(scoped);
            }
        }
        self.query_observation_source(LATEST_OBSERVATION_SOURCE_SQL, params![stable_fp])
    }

    /// Read back the whole cited source file as stored at observation time.
    /// `Ok(None)` when the blob object is gone (pruned objects dir) rather
    /// than an error, so presentation can degrade to an honest note.
    pub fn read_observation_blob(&self, blob_hash: &str) -> Result<Option<Vec<u8>>> {
        let Some(objects_dir) = self.v3_objects_dir() else {
            return Ok(None);
        };
        let hash = Blake3Hash::new(blob_hash.to_string())?;
        let store = ContentStore::open(objects_dir)?;
        if !store.object_path(&hash).is_file() {
            return Ok(None);
        }
        store.get(&hash).map(Some)
    }

    fn query_observation_source(
        &self,
        sql: &str,
        params: impl rusqlite::Params,
    ) -> Result<Option<ObservationSourceRef>> {
        self.conn
            .query_row(sql, params, |row| {
                Ok(ObservationSourceRef {
                    blob_hash: row.get(0)?,
                    display_path: row.get(1)?,
                    display_line: row.get(2)?,
                    run_id: row.get(3)?,
                })
            })
            .optional()
            .context("Could not look up the scanned-time observation source")
    }
}
