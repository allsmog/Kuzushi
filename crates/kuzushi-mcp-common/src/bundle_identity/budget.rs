use super::BundleIdentityConfig;
use anyhow::{Context, Result};

#[derive(Default)]
pub(super) struct BundleBudget {
    entries: u64,
    bytes: u64,
}

impl BundleBudget {
    pub(super) fn remaining_entry_capacity(&self, config: BundleIdentityConfig) -> Result<usize> {
        let remaining = config.max_entries.saturating_sub(self.entries);
        usize::try_from(remaining).context("bundle entry limit exceeds this platform")
    }

    pub(super) fn remaining_byte_capacity(&self, config: BundleIdentityConfig) -> Result<usize> {
        let remaining = config.max_bytes.saturating_sub(self.bytes);
        usize::try_from(remaining).context("bundle limit exceeds this platform")
    }

    pub(super) fn reserve_entry(&mut self, config: BundleIdentityConfig) -> Result<()> {
        self.entries = self
            .entries
            .checked_add(1)
            .context("bundle entry overflow")?;
        anyhow::ensure!(
            self.entries <= config.max_entries,
            "{} exceeds the {}-entry limit",
            config.label,
            config.max_entries
        );
        Ok(())
    }

    pub(super) fn reserve_bytes(&mut self, bytes: u64, config: BundleIdentityConfig) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .context("bundle byte overflow")?;
        anyhow::ensure!(
            self.bytes <= config.max_bytes,
            "{} exceeds the {}-byte limit",
            config.label,
            config.max_bytes
        );
        Ok(())
    }
}

pub(super) fn entry_limit(config: BundleIdentityConfig) -> Result<usize> {
    usize::try_from(config.max_entries).context("bundle entry limit exceeds this platform")
}
