//! Read saved recommendation inputs without silently discarding a damaged store.
use super::{recommend_scans_from_history, ScanRecommendation};
use crate::{FindingStore, ScanCancellation};
use anyhow::{Context, Result};
use std::path::Path;

pub fn load_saved_scan_recommendations(
    target: &Path,
    cancellation: Option<&ScanCancellation>,
) -> Result<Vec<ScanRecommendation>> {
    crate::sqlite_read_control::check(cancellation)?;
    let path = crate::workspace::workspace_findings_db_path(target);
    let store = match std::fs::symlink_metadata(&path) {
        Ok(_) => Some(FindingStore::open_read_only(&path)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).context("Could not inspect recommendation findings store"),
    };
    recommend_scans_from_history(target, store.as_ref(), None, cancellation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_stores_do_not_create_state_and_damaged_stores_are_not_silenced() {
        let root = tempfile::tempdir().unwrap();
        assert!(!load_saved_scan_recommendations(root.path(), None)
            .unwrap()
            .is_empty());
        assert!(!root.path().join(".kuzushi").exists());
        let path = crate::workspace::workspace_findings_db_path(root.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"Owned invalid database").unwrap();
        assert!(load_saved_scan_recommendations(root.path(), None).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"Owned invalid database");
    }

    #[test]
    fn canceled_read_stops_before_any_state_is_opened() {
        let root = tempfile::tempdir().unwrap();
        let cancellation = ScanCancellation::default();
        cancellation.cancel();
        assert!(
            load_saved_scan_recommendations(root.path(), Some(&cancellation))
                .unwrap_err()
                .to_string()
                .contains("cancelled")
        );
        assert!(!root.path().join(".kuzushi").exists());
    }
}
