use super::*;
use crate::findings::RecordedObservationSource;

const RECORDED_SOURCE_SQL: &str = r#"
select o.run_id,o.snapshot_hash,s.tree_hash,o.blob_hash,s.git_commit,s.git_branch,s.dirty_hash
  from finding_observations o
  left join target_snapshots s on s.snapshot_hash=o.snapshot_hash
 where o.finding_json is not null
   and json_extract(o.finding_json, '$.id')=?1
 order by o.created_seq desc
 limit 1
"#;

impl FindingStore {
    /// Exact generation lookup using the projected-id index. Unlike a latest
    /// identity lookup, this never substitutes a newer observation's source.
    pub fn recorded_observation_source(
        &self,
        generation_id: i64,
    ) -> Result<Option<RecordedObservationSource>> {
        self.conn
            .query_row(RECORDED_SOURCE_SQL, [generation_id], |row| {
                Ok(RecordedObservationSource {
                    schema_version: 1,
                    generation_id,
                    run_id: row.get(0)?,
                    snapshot_hash: row.get(1)?,
                    tree_hash: row.get(2)?,
                    blob_hash: row.get(3)?,
                    git_commit: row.get(4)?,
                    git_branch: row.get(5)?,
                    dirty_hash: row.get(6)?,
                })
            })
            .optional()
            .context("Could not read the recorded observation source")
    }
}

#[cfg(test)]
mod tests;
