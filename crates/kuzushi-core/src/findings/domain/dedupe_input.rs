use super::Finding;
use anyhow::{ensure, Result};

/// Bounds on the ledger preparation that happens before the model candidate cap.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DedupeLedgerLimits {
    pub max_observations: usize,
    pub max_bytes: usize,
    pub read_ms: u64,
}

impl Default for DedupeLedgerLimits {
    fn default() -> Self {
        Self {
            max_observations: 10_000,
            max_bytes: 8 * 1024 * 1024,
            read_ms: 10_000,
        }
    }
}

impl DedupeLedgerLimits {
    pub(crate) fn validate(self) -> Result<()> {
        ensure!(
            (1..=100_000).contains(&self.max_observations),
            "maxLedgerObservations must be between 1 and 100000"
        );
        ensure!(
            (1..=134_217_728).contains(&self.max_bytes),
            "maxLedgerBytes must be between 1 and 134217728"
        );
        ensure!(
            (1..=60_000).contains(&self.read_ms),
            "maxLedgerReadMs must be between 1 and 60000"
        );
        Ok(())
    }
}

/// Dedupe needs current identity, source history and suppression, without proof hydration.
pub(crate) struct DedupeLedgerRead {
    pub findings: Vec<Finding>,
    pub observations_read: usize,
    pub encoded_bytes_read: usize,
}
