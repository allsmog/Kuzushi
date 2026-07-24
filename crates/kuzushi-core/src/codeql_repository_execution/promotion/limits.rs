use anyhow::{Context, Result};

pub(super) const MAX_DATABASE_ENTRIES: u64 = 500_000;
const MAX_DATABASE_BYTES: u64 = 64_u64 * 1024 * 1024 * 1024;
pub(super) const MAX_DATABASE_DEPTH: usize = 128;

#[derive(Default)]
pub(super) struct TraversalBudget {
    entries: u64,
    bytes: u64,
}

impl TraversalBudget {
    pub(super) fn reserve_entry(&mut self) -> Result<()> {
        self.entries = self.entries.saturating_add(1);
        anyhow::ensure!(
            self.entries <= MAX_DATABASE_ENTRIES,
            "CodeQL database exceeds the file-count limit"
        );
        Ok(())
    }

    pub(super) fn remaining_entry_capacity(&self) -> usize {
        MAX_DATABASE_ENTRIES.saturating_sub(self.entries) as usize
    }

    pub(super) fn reserve_file_bytes(&mut self, bytes: u64) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .context("CodeQL database byte count overflowed")?;
        anyhow::ensure!(
            self.bytes <= MAX_DATABASE_BYTES,
            "CodeQL database exceeds the promotion byte limit"
        );
        Ok(())
    }
}
