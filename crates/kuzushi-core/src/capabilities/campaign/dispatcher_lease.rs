use anyhow::{Context, Result};
use std::path::Path;

pub struct CampaignDispatcherLease {
    _lock: crate::file_lock::ExclusiveFileLock,
}

pub fn acquire_dispatcher_lease(
    root: &Path,
    campaign_id: &str,
) -> Result<CampaignDispatcherLease> {
    let path = super::campaign_dir(root, campaign_id).join(".dispatcher.lock");
    let lock = crate::file_lock::ExclusiveFileLock::try_acquire(&path)?
        .with_context(|| format!("campaign {campaign_id:?} already has an active dispatcher"))?;
    Ok(CampaignDispatcherLease { _lock: lock })
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

        assert!(error.to_string().contains("already has an active dispatcher"));
        drop(first);
        assert!(acquire_dispatcher_lease(root.path(), "campaign-a").is_ok());
    }
}
