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
