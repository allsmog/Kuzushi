use super::walker::{self, BundleWalker};
use super::*;
use crate::{AuthorizedChild, ReadRootCapability};
use std::fs;
use std::path::Path;

const TEST_CONFIG: BundleIdentityConfig =
    BundleIdentityConfig::new(b"kuzushi-test-bundle-v1\0", "test bundle", 32, 1024, 8);

#[test]
fn copy_preserves_nested_tree_identity_and_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let destination = temp.path().join("destination");
    fs::create_dir_all(source.join("nested")).unwrap();
    fs::create_dir(&destination).unwrap();
    fs::write(source.join("root.txt"), "root").unwrap();
    fs::write(source.join("nested/child.bin"), [0_u8, 1, 2]).unwrap();

    let expected = bounded_bundle_identity(&source, TEST_CONFIG).unwrap();
    let copied = copy_bounded_bundle(&source, &destination, TEST_CONFIG).unwrap();

    #[cfg(unix)]
    assert_eq!(
        expected,
        "d77ade7b7dfe0c4d288634198079f0e102070d2996044fb38832ece053fb667a"
    );
    assert_eq!(copied, expected);
    assert_eq!(
        bounded_bundle_identity(&destination, TEST_CONFIG).unwrap(),
        expected
    );
    assert_eq!(fs::read(destination.join("root.txt")).unwrap(), b"root");
    assert_eq!(
        fs::read(destination.join("nested/child.bin")).unwrap(),
        [0_u8, 1, 2]
    );
}

#[cfg(any(unix, windows))]
#[test]
fn bundle_walker_never_accepts_a_swapped_nested_subset() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let child = source.join("child");
    let retained = temp.path().join("retained-child");
    fs::create_dir_all(&child).unwrap();
    fs::write(child.join("trusted-a"), "trusted-a").unwrap();
    fs::write(child.join("trusted-b"), "trusted-b").unwrap();
    let capability = ReadRootCapability::new([temp.path().to_path_buf()]).unwrap();
    let directory = capability.authorize_directory(&source).unwrap();
    let entry = directory.entries(4).unwrap().into_iter().next().unwrap();
    let expected = walker::hash_test_entry(&directory, &entry, TEST_CONFIG).unwrap();

    fs::rename(&child, &retained).unwrap();
    fs::create_dir(&child).unwrap();
    fs::write(child.join("decoy"), "decoy").unwrap();
    let swapped = walker::hash_test_entry(&directory, &entry, TEST_CONFIG);
    fs::remove_dir_all(&child).unwrap();
    fs::rename(&retained, &child).unwrap();

    match swapped {
        Ok(actual) => assert_eq!(actual, expected, "the retained child must be hashed"),
        Err(error) => {
            let message = format!("{error:#}");
            assert!(
                message.contains("directory entry") || message.contains("directory revision"),
                "unexpected error: {error:#}"
            );
        }
    }
    assert!(directory.verify_revision_unchanged().is_err());
}

#[cfg(any(unix, windows))]
#[test]
fn bundle_revision_receipts_reject_a_restored_same_directory_subset() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let child_path = source.join("child");
    let omitted = child_path.join("trusted-b");
    let retained = temp.path().join("retained-b");
    fs::create_dir_all(&child_path).unwrap();
    fs::write(child_path.join("trusted-a"), "trusted-a").unwrap();
    fs::write(&omitted, "trusted-b").unwrap();
    let capability = ReadRootCapability::new([temp.path().to_path_buf()]).unwrap();
    let root = capability.authorize_directory(&source).unwrap();
    let child_entry = root.entries(4).unwrap().into_iter().next().unwrap();

    fs::rename(&omitted, &retained).unwrap();
    let AuthorizedChild::Directory(child) = root.open_child(&child_entry).unwrap() else {
        panic!("child token did not open a directory");
    };
    let mut walker = BundleWalker::new(&child, None, TEST_CONFIG).unwrap();
    walker
        .hash_directory(&child, Path::new("child"), 1)
        .unwrap();
    fs::rename(&retained, &omitted).unwrap();

    let error = walker.verify_revisions_unchanged().unwrap_err();
    assert!(
        format!("{error:#}").contains("directory revision"),
        "unexpected error: {error:#}"
    );
}
