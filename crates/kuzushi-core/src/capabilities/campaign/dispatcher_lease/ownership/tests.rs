use super::*;
use crate::capabilities::campaign::{acquire_batch_controller_lease, campaign_dir};

#[test]
fn a_missing_lease_is_not_created_by_readers() {
    let root = tempfile::tempdir().unwrap();
    assert!(!batch_controller_owns_publication(root.path(), "owned").unwrap());
    assert!(!root.path().join(".kuzushi").exists());
}

#[test]
fn ownership_tracks_the_os_lease_and_leaves_its_content_unchanged() {
    let root = tempfile::tempdir().unwrap();
    let lease = acquire_batch_controller_lease(root.path(), "owned").unwrap();
    let path = campaign_dir(root.path(), "owned").join(".batch-controller.lock");
    let before = std::fs::read(&path).unwrap();
    assert!(batch_controller_owns_publication(root.path(), "owned").unwrap());
    drop(lease);
    assert!(!batch_controller_owns_publication(root.path(), "owned").unwrap());
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn invalid_ids_and_nonfile_leases_are_errors() {
    let root = tempfile::tempdir().unwrap();
    assert!(batch_controller_owns_publication(root.path(), "../outside").is_err());
    let path = campaign_dir(root.path(), "owned").join(".batch-controller.lock");
    std::fs::create_dir_all(path).unwrap();
    assert!(batch_controller_owns_publication(root.path(), "owned").is_err());
}

#[cfg(unix)]
#[test]
fn linked_lease_files_and_parents_cannot_supply_controller_ownership() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let _lease = acquire_batch_controller_lease(outside.path(), "owned").unwrap();
    let outside_campaign = campaign_dir(outside.path(), "owned");
    let local_campaign = campaign_dir(root.path(), "owned");
    std::fs::create_dir_all(&local_campaign).unwrap();
    let local_lock = local_campaign.join(".batch-controller.lock");
    symlink(outside_campaign.join(".batch-controller.lock"), &local_lock).unwrap();
    assert!(batch_controller_owns_publication(root.path(), "owned").is_err());
    std::fs::remove_file(local_lock).unwrap();
    std::fs::remove_dir(&local_campaign).unwrap();
    symlink(outside_campaign, local_campaign).unwrap();
    assert!(batch_controller_owns_publication(root.path(), "owned").is_err());
}
