use super::model::{RunHistoryIndexEntry, MAX_ISSUE_JSON_BYTES};
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::BinaryHeap;

pub(super) const DEFAULT_MAX_RETAINED_ROWS: usize = 4_096;
pub(super) const DEFAULT_MAX_RETAINED_BYTES: u64 = 32 * 1024 * 1024;
const MAX_CONFIGURED_ROWS: usize = 100_000;
const MAX_CONFIGURED_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ENTRY_SLACK_BYTES: u64 = MAX_ISSUE_JSON_BYTES as u64 + 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RetentionPolicy {
    pub max_rows: usize,
    pub max_bytes: u64,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            max_rows: DEFAULT_MAX_RETAINED_ROWS,
            max_bytes: DEFAULT_MAX_RETAINED_BYTES,
        }
    }
}

impl RetentionPolicy {
    pub(super) fn validate(self) -> Result<Self> {
        anyhow::ensure!(
            self.max_rows > 0 && self.max_rows <= MAX_CONFIGURED_ROWS,
            "run-history retained row limit is invalid"
        );
        anyhow::ensure!(
            self.max_bytes > 0 && self.max_bytes <= MAX_CONFIGURED_BYTES,
            "run-history retained byte limit is invalid"
        );
        Ok(self)
    }
}

pub(super) struct RetentionBuilder {
    policy: RetentionPolicy,
    heap: BinaryHeap<RunHistoryIndexEntry>,
    retained_bytes: u64,
    canonical_total: u64,
    canonical_xor: [u8; 32],
}

pub(super) struct RetainedHistory {
    pub entries: Vec<RunHistoryIndexEntry>,
    pub retained_bytes: u64,
    pub canonical_total: u64,
    pub canonical_xor: [u8; 32],
}

impl RetentionBuilder {
    pub(super) fn new(policy: RetentionPolicy) -> Result<Self> {
        Ok(Self {
            policy: policy.validate()?,
            heap: BinaryHeap::new(),
            retained_bytes: 0,
            canonical_total: 0,
            canonical_xor: [0; 32],
        })
    }

    pub(super) fn push(&mut self, entry: RunHistoryIndexEntry) -> Result<()> {
        entry.validate()?;
        self.canonical_total = self
            .canonical_total
            .checked_add(1)
            .context("run-history canonical total overflowed")?;
        xor_digest(&mut self.canonical_xor, &entry_digest(&entry)?);
        self.retained_bytes = self
            .retained_bytes
            .checked_add(entry.retained_bytes()?)
            .context("run-history retained bytes overflowed")?;
        self.heap.push(entry);
        self.prune_tail()
    }

    pub(super) fn finish(self) -> Result<RetainedHistory> {
        let (entries, retained_bytes) =
            retain_canonical_prefix(self.heap.into_sorted_vec(), self.policy)?;
        Ok(RetainedHistory {
            entries,
            retained_bytes,
            canonical_total: self.canonical_total,
            canonical_xor: self.canonical_xor,
        })
    }

    fn prune_tail(&mut self) -> Result<()> {
        let byte_ceiling = self.policy.max_bytes.saturating_add(MAX_ENTRY_SLACK_BYTES);
        while self.heap.len() > self.policy.max_rows || self.retained_bytes > byte_ceiling {
            let removed = self
                .heap
                .pop()
                .context("run-history retention heap unexpectedly empty")?;
            self.retained_bytes = self
                .retained_bytes
                .checked_sub(removed.retained_bytes()?)
                .context("run-history retained byte accounting underflowed")?;
        }
        Ok(())
    }
}

pub(super) fn retain_canonical_prefix(
    mut entries: Vec<RunHistoryIndexEntry>,
    policy: RetentionPolicy,
) -> Result<(Vec<RunHistoryIndexEntry>, u64)> {
    let policy = policy.validate()?;
    entries.sort();
    let mut retained = Vec::with_capacity(entries.len().min(policy.max_rows));
    let mut retained_bytes = 0_u64;
    for entry in entries {
        if retained.len() == policy.max_rows {
            break;
        }
        let next_bytes = retained_bytes
            .checked_add(entry.retained_bytes()?)
            .context("run-history retained bytes overflowed")?;
        if next_bytes > policy.max_bytes {
            break;
        }
        retained_bytes = next_bytes;
        retained.push(entry);
    }
    Ok((retained, retained_bytes))
}

pub(super) fn entry_digest(entry: &RunHistoryIndexEntry) -> Result<[u8; 32]> {
    Ok(Sha256::digest(entry.canonical_bytes()?).into())
}

pub(super) fn xor_digest(accumulator: &mut [u8; 32], digest: &[u8; 32]) {
    for (target, value) in accumulator.iter_mut().zip(digest) {
        *target ^= value;
    }
}

pub(super) fn entries_xor(entries: &[RunHistoryIndexEntry]) -> Result<[u8; 32]> {
    let mut accumulator = [0; 32];
    for entry in entries {
        xor_digest(&mut accumulator, &entry_digest(entry)?);
    }
    Ok(accumulator)
}

pub(super) fn canonical_digest(total: u64, xor: &[u8; 32]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"kuzushi-run-history-canonical-v1\0");
    digest.update(total.to_le_bytes());
    digest.update(xor);
    format!("sha256:{}", hex_bytes(&digest.finalize()))
}

pub(super) fn table_digest(entries: &[RunHistoryIndexEntry]) -> Result<String> {
    let mut digest = Sha256::new();
    digest.update(b"kuzushi-run-history-table-v1\0");
    for entry in entries {
        let encoded = entry.canonical_bytes()?;
        digest.update((encoded.len() as u64).to_le_bytes());
        digest.update(encoded);
    }
    Ok(format!("sha256:{}", hex_bytes(&digest.finalize())))
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streaming_builder_bounds_large_histories() {
        let policy = RetentionPolicy {
            max_rows: 7,
            max_bytes: 4_096,
        };
        let mut builder = RetentionBuilder::new(policy).unwrap();
        for index in 0..20_000_u64 {
            builder
                .push(RunHistoryIndexEntry {
                    run_id: format!("run-{index:05}"),
                    started_at_unix: Some(index),
                    issue: None,
                })
                .unwrap();
        }

        let retained = builder.finish().unwrap();

        assert_eq!(retained.canonical_total, 20_000);
        assert_eq!(retained.entries.len(), 7);
        assert_eq!(retained.entries[0].run_id, "run-19999");
        assert_eq!(retained.entries[6].run_id, "run-19993");
        assert!(retained.retained_bytes <= policy.max_bytes);
    }
}
