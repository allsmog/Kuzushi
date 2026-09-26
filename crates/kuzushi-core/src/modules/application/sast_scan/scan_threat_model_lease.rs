//! The shared threat-model lease a scan holds while it consumes the bound
//! model revision. A post-scan refine commits a new revision, which takes the
//! exclusive side of the same store lock, so the scan must release its lease
//! first or it waits on itself forever.

use crate::capabilities::threat_model::ThreatModelReadLease;
use std::cell::Cell;

pub(in crate::modules) struct ScanThreatModelLease {
    lease: Cell<Option<ThreatModelReadLease>>,
}

impl ScanThreatModelLease {
    pub(in crate::modules) fn new(lease: Option<ThreatModelReadLease>) -> Self {
        Self { lease: Cell::new(lease) }
    }

    /// Stop holding the bound revision. Call only once the scan no longer
    /// reads the model, before anything that commits a new revision.
    pub(in crate::modules) fn release(&self) {
        drop(self.lease.take());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::threat_model::{
        acquire_threat_model_read_lease, threat_model_store_accepts_commits,
    };

    #[test]
    fn releasing_the_scan_lease_lets_a_refine_commit() {
        let temp = tempfile::tempdir().unwrap();
        let lease = ScanThreatModelLease::new(Some(
            acquire_threat_model_read_lease(temp.path()).unwrap(),
        ));
        assert!(!threat_model_store_accepts_commits(temp.path()).unwrap());

        lease.release();

        assert!(threat_model_store_accepts_commits(temp.path()).unwrap());
    }
}
