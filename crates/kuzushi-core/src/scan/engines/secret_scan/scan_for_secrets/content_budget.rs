use super::*;

pub(super) struct ContentBudget {
    maximum: u64,
    pub(super) reserved: u64,
}

impl ContentBudget {
    pub(super) fn new(maximum: u64) -> Self {
        Self {
            maximum,
            reserved: 0,
        }
    }

    /// The bounded reader can inspect one additional byte to detect growth.
    pub(super) fn reserve(&mut self, length: u64) -> Result<()> {
        let charge = length
            .checked_add(1)
            .context("Content read reservation overflow")?;
        anyhow::ensure!(
            charge <= self.maximum.saturating_sub(self.reserved),
            "total content read allowance reached ({} bytes); this file was not inspected",
            self.maximum
        );
        self.reserved += charge;
        Ok(())
    }
}
