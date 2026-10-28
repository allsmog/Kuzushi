use anyhow::{Context, Result};
use std::path::Path;

mod ownership;
pub(crate) use ownership::batch_controller_owns_publication;

pub struct CampaignDispatcherLease {
    _lock: crate::file_lock::ExclusiveFileLock,
    control: super::CampaignDispatcherControl,
}

impl CampaignDispatcherLease {
    pub fn control(&self) -> super::CampaignDispatcherControl {
        self.control.clone()
    }
}

pub struct BatchControllerLease {
    _lock: crate::file_lock::ExclusiveFileLock,
}

pub fn acquire_dispatcher_lease(root: &Path, campaign_id: &str) -> Result<CampaignDispatcherLease> {
    let path = super::campaign_dir(root, campaign_id).join(".dispatcher.lock");
    let lock = crate::file_lock::ExclusiveFileLock::try_acquire(&path)?
        .with_context(|| format!("campaign {campaign_id:?} already has an active dispatcher"))?;
    let control = super::CampaignDispatcherControl::publish(root, campaign_id)?;
    Ok(CampaignDispatcherLease {
        _lock: lock,
        control,
    })
}

pub fn acquire_batch_controller_lease(root: &Path, batch_id: &str) -> Result<BatchControllerLease> {
    let path = super::campaign_dir(root, batch_id).join(".batch-controller.lock");
    let lock = crate::file_lock::ExclusiveFileLock::try_acquire(&path)?
        .with_context(|| format!("scan batch {batch_id:?} already has an active controller"))?;
    Ok(BatchControllerLease { _lock: lock })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn campaign_dispatcher_lease_is_exclusive() {
        let root = tempfile::tempdir().unwrap();
        let first = acquire_dispatcher_lease(root.path(), "campaign-a").unwrap();

        let error = acquire_dispatcher_lease(root.path(), "campaign-a")
            .err()
            .expect("second dispatcher must be refused");

        assert!(error
            .to_string()
            .contains("already has an active dispatcher"));
        drop(first);
        assert!(acquire_dispatcher_lease(root.path(), "campaign-a").is_ok());
    }

    #[test]
    fn batch_controller_lease_spans_dispatch_and_aggregation() {
        let root = tempfile::tempdir().unwrap();
        let first = acquire_batch_controller_lease(root.path(), "batch-a").unwrap();
        assert!(acquire_batch_controller_lease(root.path(), "batch-a").is_err());
        drop(first);
        assert!(acquire_batch_controller_lease(root.path(), "batch-a").is_ok());
    }
}
