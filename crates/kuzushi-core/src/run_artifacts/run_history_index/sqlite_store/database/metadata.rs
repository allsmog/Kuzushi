use super::super::super::super::checked_runs_root;
use super::super::super::model::{RunHistoryCursor, RunHistoryIndexEntry, RunHistoryPageInfo};
use super::super::super::retention::{
    canonical_digest, entries_xor, table_digest, RetentionPolicy,
};
use anyhow::{Context, Result};
use rusqlite::{Connection, Transaction};
use std::fs;
use std::path::Path;
use std::time::UNIX_EPOCH;

mod sqlite;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::run_artifacts::run_history_index) struct DirectoryStamp {
    present: bool,
    secs: i64,
    nanos: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::run_artifacts::run_history_index::sqlite_store) struct DirectorySnapshot {
    pub(in crate::run_artifacts::run_history_index::sqlite_store) stamp: DirectoryStamp,
    pub(in crate::run_artifacts::run_history_index::sqlite_store) entry_count: u64,
}

#[derive(Debug, Clone)]
pub(in crate::run_artifacts::run_history_index::sqlite_store) struct IndexMetadata {
    pub(in crate::run_artifacts::run_history_index::sqlite_store) stamp: DirectoryStamp,
    pub(in crate::run_artifacts::run_history_index::sqlite_store) canonical_total: u64,
    pub(in crate::run_artifacts::run_history_index::sqlite_store) retained_count: u64,
    pub(in crate::run_artifacts::run_history_index::sqlite_store) retained_bytes: u64,
    pub(in crate::run_artifacts::run_history_index::sqlite_store) policy: RetentionPolicy,
    pub(in crate::run_artifacts::run_history_index::sqlite_store) oldest_retained:
        Option<RunHistoryCursor>,
    pub(in crate::run_artifacts::run_history_index::sqlite_store) truncated: bool,
    pub(in crate::run_artifacts::run_history_index::sqlite_store) generation: u64,
    pub(in crate::run_artifacts::run_history_index::sqlite_store) canonical_xor: [u8; 32],
    canonical_digest: String,
    table_digest: String,
}

impl IndexMetadata {
    pub(in crate::run_artifacts::run_history_index::sqlite_store) fn validate_header(
        &self,
    ) -> Result<()> {
        self.validate_fields()
    }

    pub(in crate::run_artifacts::run_history_index::sqlite_store) fn page_info(
        &self,
    ) -> RunHistoryPageInfo {
        RunHistoryPageInfo {
            canonical_total: self.canonical_total,
            retained_count: self.retained_count,
            retained_bytes: self.retained_bytes,
            retention_max_rows: self.policy.max_rows,
            retention_max_bytes: self.policy.max_bytes,
            oldest_retained: self.oldest_retained.clone(),
            truncated: self.truncated,
            generation: self.generation,
            canonical_digest: self.canonical_digest.clone(),
            table_digest: self.table_digest.clone(),
        }
    }

    pub(in crate::run_artifacts::run_history_index::sqlite_store) fn from_entries(
        stamp: DirectoryStamp,
        canonical_total: u64,
        canonical_xor: [u8; 32],
        policy: RetentionPolicy,
        generation: u64,
        entries: &[RunHistoryIndexEntry],
    ) -> Result<Self> {
        let retained_bytes = entries.iter().try_fold(0_u64, |total, entry| {
            total
                .checked_add(entry.retained_bytes()?)
                .context("run-history retained byte count overflowed")
        })?;
        let retained_count =
            u64::try_from(entries.len()).context("run-history retained count does not fit u64")?;
        Ok(Self {
            stamp,
            canonical_total,
            retained_count,
            retained_bytes,
            policy: policy.validate()?,
            oldest_retained: entries.last().map(|entry| entry.cursor(generation)),
            truncated: canonical_total > retained_count,
            generation,
            canonical_xor,
            canonical_digest: canonical_digest(canonical_total, &canonical_xor),
            table_digest: table_digest(entries)?,
        })
    }

    pub(in crate::run_artifacts::run_history_index::sqlite_store) fn load(
        connection: &Connection,
    ) -> Result<Self> {
        sqlite::load(connection)
    }

    pub(in crate::run_artifacts::run_history_index::sqlite_store) fn write(
        &self,
        transaction: &Transaction<'_>,
    ) -> Result<()> {
        sqlite::write(self, transaction)
    }

    pub(in crate::run_artifacts::run_history_index::sqlite_store) fn validate(
        &self,
        target: &Path,
        entries: &[RunHistoryIndexEntry],
    ) -> Result<()> {
        anyhow::ensure!(
            self.stamp == directory_stamp(target)?,
            "run-history index is stale"
        );
        self.validate_rows(target, entries)
    }

    pub(in crate::run_artifacts::run_history_index::sqlite_store) fn validate_rows(
        &self,
        _target: &Path,
        entries: &[RunHistoryIndexEntry],
    ) -> Result<()> {
        self.validate_fields()?;
        let expected = Self::from_entries(
            self.stamp,
            self.canonical_total,
            self.canonical_xor,
            self.policy,
            self.generation,
            entries,
        )?;
        anyhow::ensure!(
            self.retained_count == expected.retained_count
                && self.retained_bytes == expected.retained_bytes
                && self.oldest_retained == expected.oldest_retained
                && self.truncated == expected.truncated
                && self.canonical_digest == expected.canonical_digest
                && self.table_digest == expected.table_digest,
            "run-history index metadata does not match retained rows"
        );
        if !self.truncated {
            anyhow::ensure!(
                self.canonical_xor == entries_xor(entries)?,
                "run-history canonical digest does not match complete rows"
            );
        }
        Ok(())
    }

    fn validate_fields(&self) -> Result<()> {
        self.policy.validate()?;
        anyhow::ensure!(self.generation > 0, "run-history generation is invalid");
        anyhow::ensure!(
            self.retained_count <= self.canonical_total,
            "run-history retained count exceeds canonical total"
        );
        anyhow::ensure!(
            self.retained_count <= self.policy.max_rows as u64
                && self.retained_bytes <= self.policy.max_bytes,
            "run-history retention metadata exceeds policy"
        );
        anyhow::ensure!(
            self.truncated == (self.canonical_total > self.retained_count),
            "run-history truncation metadata is invalid"
        );
        anyhow::ensure!(
            self.oldest_retained.is_some() == (self.retained_count > 0),
            "run-history oldest cursor metadata is invalid"
        );
        if let Some(cursor) = &self.oldest_retained {
            cursor.validate()?;
            anyhow::ensure!(
                cursor.generation == self.generation,
                "run-history oldest cursor generation is invalid"
            );
        }
        Ok(())
    }

    fn oldest_sql_values(&self) -> Result<(Option<i64>, Option<i64>, Option<&str>, Option<&str>)> {
        let Some(cursor) = &self.oldest_retained else {
            return Ok((None, None, None, None));
        };
        let (state, started, ready, issue) = cursor.sqlite_values()?;
        Ok((Some(state), Some(started), Some(ready), Some(issue)))
    }
}

pub(in crate::run_artifacts::run_history_index::sqlite_store) fn directory_stamp(
    target: &Path,
) -> Result<DirectoryStamp> {
    let root = checked_runs_root(target)?;
    let Some(metadata) = directory_metadata(&root)? else {
        return Ok(DirectoryStamp {
            present: false,
            secs: 0,
            nanos: 0,
        });
    };
    let duration = metadata
        .modified()?
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    Ok(DirectoryStamp {
        present: true,
        secs: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        nanos: i64::from(duration.subsec_nanos()),
    })
}

pub(in crate::run_artifacts::run_history_index::sqlite_store) fn stable_directory_snapshot(
    target: &Path,
) -> Result<DirectorySnapshot> {
    let before = directory_stamp(target)?;
    let root = checked_runs_root(target)?;
    #[cfg(test)]
    apply_external_mkdir_test_hook(target, &root)?;
    let entry_count = if before.present {
        fs::read_dir(&root)
            .with_context(|| format!("Could not read {}", root.display()))?
            .try_fold(0_u64, |count, entry| {
                entry?;
                count
                    .checked_add(1)
                    .context("run-history directory count overflowed")
            })?
    } else {
        0
    };
    let after = directory_stamp(target)?;
    anyhow::ensure!(
        before == after,
        "run-history directory changed while it was counted"
    );
    Ok(DirectorySnapshot {
        stamp: after,
        entry_count,
    })
}

#[cfg(test)]
pub(in crate::run_artifacts::run_history_index::sqlite_store) fn external_mkdir_test_hook_path(
    target: &Path,
) -> Result<std::path::PathBuf> {
    let root = checked_runs_root(target)?;
    Ok(root
        .parent()
        .context("run-history root has no parent")?
        .join("run-history.test-external-mkdir"))
}

#[cfg(test)]
fn apply_external_mkdir_test_hook(target: &Path, root: &Path) -> Result<()> {
    let hook = external_mkdir_test_hook_path(target)?;
    let run_id = match fs::read_to_string(&hook) {
        Ok(value) => value.trim().to_string(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    fs::remove_file(&hook)?;
    fs::create_dir_all(root.join(run_id))?;
    Ok(())
}

fn directory_metadata(path: &Path) -> Result<Option<fs::Metadata>> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
    }
}
