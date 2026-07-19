use super::*;

#[test]
fn resolves_absolute_and_relative_paths_inside_a_root() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("src/main.rs");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, "fn main() {}\n").unwrap();
    let capability = ReadRootCapability::new([root.path().to_path_buf()]).unwrap();

    assert_eq!(
        capability.resolve(Path::new("src/main.rs")).unwrap(),
        std::fs::canonicalize(&file).unwrap()
    );
    assert_eq!(
        capability.resolve(&file).unwrap(),
        std::fs::canonicalize(&file).unwrap()
    );
}

#[test]
fn rejects_paths_outside_the_declared_roots() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    let capability = ReadRootCapability::new([root.path().to_path_buf()]).unwrap();

    let error = capability.resolve(outside.path()).unwrap_err();
    assert!(error.to_string().contains("outside the MCP read roots"));
}

#[test]
fn reads_utf8_and_binary_files_with_an_exact_bound() {
    let root = tempfile::tempdir().unwrap();
    let text = root.path().join("note.txt");
    let binary = root.path().join("blob.bin");
    std::fs::write(&text, "hello").unwrap();
    std::fs::write(&binary, [0_u8, 1, 2]).unwrap();
    let capability = ReadRootCapability::new([root.path().to_path_buf()]).unwrap();

    assert_eq!(capability.read_utf8(&text, 5).unwrap(), "hello");
    assert_eq!(capability.read_bytes(&binary, 3).unwrap(), [0, 1, 2]);
}

#[test]
fn bounded_copy_streams_and_hashes_the_authorized_bytes() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("blob.bin");
    std::fs::write(&file, b"abc").unwrap();
    let capability = ReadRootCapability::new([root.path().to_path_buf()]).unwrap();
    let mut copied = Vec::new();

    let hash = capability
        .open_strict(&file, 3)
        .unwrap()
        .copy_to_with_sha256_hex(&mut copied)
        .unwrap();

    assert_eq!(copied, b"abc");
    assert_eq!(
        hash,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn rejects_oversized_files_before_reading_them() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("large.bin");
    std::fs::write(&file, [0_u8; 9]).unwrap();
    let capability = ReadRootCapability::new([root.path().to_path_buf()]).unwrap();

    let error = capability.read_bytes(&file, 8).unwrap_err();

    assert!(error
        .to_string()
        .contains("maximum supported size of 8 bytes"));
}

#[test]
fn strict_directory_children_reject_absolute_and_parent_paths() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("src/main.c");
    std::fs::create_dir_all(source.parent().unwrap()).unwrap();
    std::fs::write(&source, "int main(void) {}\n").unwrap();
    let capability = ReadRootCapability::new([root.path().to_path_buf()]).unwrap();
    let directory = capability.authorize_directory(root.path()).unwrap();

    assert_eq!(
        directory
            .open_file(Path::new("src/main.c"), 64)
            .unwrap()
            .read_utf8()
            .unwrap(),
        "int main(void) {}\n"
    );
    assert!(directory.open_file(&source, 64).is_err());
    assert!(directory.open_file(Path::new("../main.c"), 64).is_err());
}

#[cfg(any(unix, windows))]
#[test]
fn retained_directory_enumeration_ignores_a_visible_leaf_swap() {
    assert_retained_names_during_swap(Path::new("scope"), Path::new("scope"));
}

#[cfg(any(unix, windows))]
#[test]
fn retained_directory_enumeration_ignores_an_ancestor_swap() {
    assert_retained_names_during_swap(Path::new("scope/parent"), Path::new("scope"));
}

#[cfg(any(unix, windows))]
fn assert_retained_names_during_swap(authorized: &Path, swapped: &Path) {
    let outer = tempfile::tempdir().unwrap();
    let authorized = outer.path().join(authorized);
    let swapped = outer.path().join(swapped);
    let retained = outer.path().join("retained-scope");
    std::fs::create_dir_all(&authorized).unwrap();
    std::fs::write(authorized.join("trusted"), "trusted").unwrap();
    let capability = ReadRootCapability::new([outer.path().to_path_buf()]).unwrap();
    let directory = capability.authorize_directory(&authorized).unwrap();

    std::fs::rename(&swapped, &retained).unwrap();
    std::fs::create_dir_all(&authorized).unwrap();
    std::fs::write(authorized.join("decoy"), "decoy").unwrap();
    let first = directory.entry_names(4).unwrap();
    let second = directory.entry_names(4).unwrap();
    std::fs::remove_dir_all(&swapped).unwrap();
    std::fs::rename(&retained, &swapped).unwrap();

    assert_eq!(first, [std::ffi::OsString::from("trusted")]);
    assert_eq!(second, first, "enumeration must restart on each call");
    directory.verify_unchanged().unwrap();
}

#[cfg(any(unix, windows))]
#[test]
fn retained_directory_enumeration_enforces_its_entry_bound() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("one"), "one").unwrap();
    std::fs::write(root.path().join("two"), "two").unwrap();
    let capability = ReadRootCapability::new([root.path().to_path_buf()]).unwrap();
    let directory = capability.authorize_directory(root.path()).unwrap();

    let error = directory.entry_names(1).unwrap_err().to_string();

    assert!(error.contains("1-entry limit"), "{error}");
}

#[cfg(any(unix, windows))]
#[test]
fn enumerated_child_token_never_opens_a_path_replacement() {
    let root = tempfile::tempdir().unwrap();
    let trusted = root.path().join("artifact");
    let retained = root.path().join("retained-artifact");
    std::fs::write(&trusted, "trusted").unwrap();
    let capability = ReadRootCapability::new([root.path().to_path_buf()]).unwrap();
    let directory = capability.authorize_directory(root.path()).unwrap();
    let entry = directory.entries(4).unwrap().into_iter().next().unwrap();

    std::fs::rename(&trusted, &retained).unwrap();
    std::fs::write(&trusted, "replacement").unwrap();
    match directory.open_child(&entry) {
        Ok(AuthorizedChild::File(file)) => {
            let bytes = file.into_bounded(64).unwrap().read_utf8().unwrap();
            assert_eq!(bytes, "trusted", "the retained file ID must win");
        }
        Ok(AuthorizedChild::Directory(_)) => panic!("file token opened a directory"),
        Err(error) => assert!(
            format!("{error:#}").contains("directory entry"),
            "unexpected error: {error:#}"
        ),
    }
    std::fs::remove_file(&trusted).unwrap();
    std::fs::rename(&retained, &trusted).unwrap();

    assert!(directory.verify_revision_unchanged().is_err());
}

#[cfg(unix)]
#[test]
fn unix_directory_tokens_open_a_nested_mount_root() {
    use std::os::unix::fs::MetadataExt;

    let root_device = std::fs::metadata("/").unwrap().dev();
    let dev_device = std::fs::metadata("/dev").unwrap().dev();
    if root_device == dev_device {
        eprintln!("skipping nested-mount regression: /dev shares the / device");
        return;
    }
    let capability = ReadRootCapability::new([PathBuf::from("/")]).unwrap();
    let root = capability.authorize_directory(Path::new("/")).unwrap();
    let dev = root
        .entries(4096)
        .unwrap()
        .into_iter()
        .find(|entry| entry.name() == std::ffi::OsStr::new("dev"))
        .expect("the Unix root should contain /dev");

    let AuthorizedChild::Directory(dev) = root.open_child(&dev).unwrap() else {
        panic!("/dev token did not open a directory");
    };

    assert_eq!(dev.path(), Path::new("/dev"));
}

#[cfg(unix)]
#[test]
fn unix_directory_tokens_reject_special_files_before_opening() {
    use std::os::unix::ffi::OsStrExt;

    let root = tempfile::tempdir().unwrap();
    let fifo = root.path().join("pipe");
    let fifo_name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: the path is NUL-terminated and names a new entry in a live
    // temporary directory.
    assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
    let capability = ReadRootCapability::new([root.path().to_path_buf()]).unwrap();
    let directory = capability.authorize_directory(root.path()).unwrap();
    let entry = directory.entries(1).unwrap().into_iter().next().unwrap();

    let error = directory.open_child(&entry).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("not a regular file or directory"),
        "{error:#}"
    );
}

#[cfg(windows)]
#[test]
fn windows_directory_enumeration_continues_across_multiple_batches() {
    let root = tempfile::tempdir().unwrap();
    for index in 0..600 {
        let name = format!("{index:04}-{}", "x".repeat(180));
        std::fs::write(root.path().join(name), "entry").unwrap();
    }
    let capability = ReadRootCapability::new([root.path().to_path_buf()]).unwrap();
    let directory = capability.authorize_directory(root.path()).unwrap();

    let entries = directory.entries(600).unwrap();

    assert_eq!(entries.len(), 600);
}

#[cfg(unix)]
#[test]
fn strict_open_rejects_symlinks_even_when_the_target_is_inside_the_root() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("target.txt");
    let link = root.path().join("link.txt");
    std::fs::write(&target, "inside").unwrap();
    symlink(&target, &link).unwrap();
    let capability = ReadRootCapability::new([root.path().to_path_buf()]).unwrap();

    assert!(capability.open_strict(&link, 32).is_err());
}

#[cfg(unix)]
#[test]
fn authorized_directory_detects_a_visible_root_replacement() {
    let outer = tempfile::tempdir().unwrap();
    let scope = outer.path().join("scope");
    let retained = outer.path().join("retained");
    std::fs::create_dir(&scope).unwrap();
    let capability = ReadRootCapability::new([scope.clone()]).unwrap();
    let directory = capability.authorize_directory(&scope).unwrap();

    std::fs::rename(&scope, &retained).unwrap();
    std::fs::create_dir(&scope).unwrap();

    let error = directory.verify_unchanged().unwrap_err();
    assert!(error.to_string().contains("changed after authorization"));
}

#[test]
fn rejects_bytes_when_the_opened_file_identity_changes() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("mutable.txt");
    std::fs::write(&file, "before").unwrap();
    let capability = ReadRootCapability::new([root.path().to_path_buf()]).unwrap();
    let opened = capability.open(&file, 32).unwrap();

    std::fs::write(&file, "after!").unwrap();
    let error = opened.read_bytes().unwrap_err();

    assert!(error
        .to_string()
        .contains("changed while it was being read"));
}

#[cfg(unix)]
#[test]
fn rejects_symlinks_that_escape_a_root() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    let link = root.path().join("escape");
    symlink(outside.path(), &link).unwrap();
    let capability = ReadRootCapability::new([root.path().to_path_buf()]).unwrap();

    let error = capability.resolve(&link).unwrap_err();
    assert!(error.to_string().contains("outside the MCP read roots"));
}

#[cfg(unix)]
#[test]
fn reauthorizes_a_path_replaced_with_an_escaping_symlink() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("artifact.json");
    let outside = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(&file, "inside").unwrap();
    let capability = ReadRootCapability::new([root.path().to_path_buf()]).unwrap();
    assert_eq!(capability.read_utf8(&file, 32).unwrap(), "inside");

    std::fs::remove_file(&file).unwrap();
    symlink(outside.path(), &file).unwrap();
    let error = capability.read_utf8(&file, 32).unwrap_err();

    assert!(error.to_string().contains("outside the MCP read roots"));
}

#[cfg(windows)]
#[test]
fn rejects_a_replaced_root_after_path_resolution() {
    let outer = tempfile::tempdir().unwrap();
    let scope = outer.path().join("scope");
    let retained = outer.path().join("retained-scope");
    let requested = scope.join("artifact.txt");
    std::fs::create_dir(&scope).unwrap();
    std::fs::write(&requested, "authorized").unwrap();
    let capability = ReadRootCapability::new([scope.clone()]).unwrap();
    let resolved = capability.resolve(&requested).unwrap();

    std::fs::rename(&scope, &retained).unwrap();
    std::fs::create_dir(&scope).unwrap();
    std::fs::write(&requested, "replacement").unwrap();
    let root = capability.root_for(&resolved).unwrap();
    let error = super::open::open_file_beneath(root, &resolved).unwrap_err();

    assert!(error.to_string().contains("escaped the retained read root"));
}

#[cfg(windows)]
#[test]
fn authorizes_the_retained_root_directory_itself() {
    let root = tempfile::tempdir().unwrap();
    let capability = ReadRootCapability::new([root.path().to_path_buf()]).unwrap();

    let directory = capability.authorize_directory(root.path()).unwrap();

    assert_eq!(
        directory.path(),
        std::fs::canonicalize(root.path()).unwrap()
    );
    directory.verify_unchanged().unwrap();
}

#[cfg(windows)]
#[test]
fn rejects_a_parent_junction_swapped_after_path_resolution() {
    let outer = tempfile::tempdir().unwrap();
    let scope = outer.path().join("scope");
    let parent = scope.join("parent");
    let moved_parent = scope.join("original-parent");
    let outside = outer.path().join("outside");
    let requested = parent.join("artifact.txt");
    std::fs::create_dir_all(&parent).unwrap();
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(&requested, "authorized").unwrap();
    std::fs::write(outside.join("artifact.txt"), "outside").unwrap();
    let capability = ReadRootCapability::new([scope.clone()]).unwrap();
    let resolved = capability.resolve(&requested).unwrap();

    std::fs::rename(&parent, &moved_parent).unwrap();
    create_windows_junction(&parent, &outside);
    let root = capability.root_for(&resolved).unwrap();
    let error = super::open::open_file_beneath(root, &resolved).unwrap_err();

    assert!(error.to_string().contains("escaped the retained read root"));
}

#[cfg(windows)]
fn create_windows_junction(link: &Path, target: &Path) {
    let output = std::process::Command::new("cmd")
        .arg("/C")
        .arg("mklink")
        .arg("/J")
        .arg(link)
        .arg(target)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "mklink /J failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
