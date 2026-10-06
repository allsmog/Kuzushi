use super::*;
use crate::content_store::ContentStore;
use crate::identity::Blake3Hash;

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
