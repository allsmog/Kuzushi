use super::*;

/// Holds the store's shared lock while a scan consumes the active immutable
/// object. Activations and revision commits take the exclusive side of this
/// lock, so manifest-aware readers cannot observe a pointer switch mid-scan.
pub(crate) struct ThreatModelReadLease {
    model_ref: Option<ThreatModelRef>,
    _lock: crate::file_lock::SharedFileLock,
}

impl ThreatModelReadLease {
    pub(crate) fn model_ref(&self) -> Option<&ThreatModelRef> {
        self.model_ref.as_ref()
    }
}

pub(crate) fn acquire_threat_model_read_lease(root: &Path) -> Result<ThreatModelReadLease> {
    prepare_store_directories(root)?;
    let lock = acquire_store_read_lock(root)?;
    let model_ref = load_active_threat_model(root)?.map(|active| active.model_ref);
    Ok(ThreatModelReadLease {
        model_ref,
        _lock: lock,
    })
}

pub(crate) fn acquire_exact_threat_model_read_lease(
    root: &Path,
    expected: Option<&ThreatModelRef>,
) -> Result<ThreatModelReadLease> {
    let lease = acquire_threat_model_read_lease(root)?;
    anyhow::ensure!(
        lease.model_ref() == expected,
        "active threat model changed before the bound scan started (expected {}, found {})",
        threat_model_ref_label(expected),
        threat_model_ref_label(lease.model_ref())
    );
    Ok(lease)
}

/// Whether a revision commit could take the store's exclusive lock right now.
#[cfg(test)]
pub(crate) fn threat_model_store_accepts_commits(root: &Path) -> Result<bool> {
    let path = threat_model_store_path(root).join(STORE_LOCK);
    Ok(crate::file_lock::ExclusiveFileLock::try_acquire(&path)?.is_some())
}

fn threat_model_ref_label(model_ref: Option<&ThreatModelRef>) -> String {
    model_ref
        .map(|value| {
            format!(
                "{}@{} ({})",
                value.model_id, value.revision_id, value.sha256
            )
        })
        .unwrap_or_else(|| "no active model".to_string())
}
