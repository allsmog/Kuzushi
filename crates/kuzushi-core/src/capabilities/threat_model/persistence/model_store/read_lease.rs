use super::*;

/// Active selection holds a short read lock while compiling a plan. Exact
/// selection authenticates the immutable object without locking the active
/// pointer for the duration of an investigation.
pub(crate) struct ThreatModelReadLease {
    model_ref: Option<ThreatModelRef>,
    _lock: Option<crate::file_lock::SharedFileLock>,
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
        _lock: Some(lock),
    })
}

pub(crate) fn acquire_exact_threat_model_read_lease(
    root: &Path,
    expected: Option<&ThreatModelRef>,
) -> Result<ThreatModelReadLease> {
    if let Some(reference) = expected {
        super::super::selection::load_exact_threat_model(root, reference)?;
    }
    Ok(ThreatModelReadLease { model_ref: expected.cloned(), _lock: None })
}

/// Whether a revision commit could take the store's exclusive lock right now.
#[cfg(test)]
pub(crate) fn threat_model_store_accepts_commits(root: &Path) -> Result<bool> {
    let path = threat_model_store_path(root).join(STORE_LOCK);
    Ok(crate::file_lock::ExclusiveFileLock::try_acquire(&path)?.is_some())

}
