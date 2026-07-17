use super::*;

fn oid() -> &'static str {
    "1111111111111111111111111111111111111111"
}

fn record(mode: &str, kind: &str, size: u64, path: &str) -> Vec<u8> {
    format!("{mode} {kind} {} {size}\t{path}\0", oid()).into_bytes()
}

fn limits() -> MaterializationLimits {
    MaterializationLimits {
        max_files: 2,
        max_file_bytes: 8,
        max_total_bytes: 12,
        max_path_bytes: 32,
        max_index_bytes: 256,
        max_batch_request_bytes: 128,
        max_batch_stream_bytes: 512,
        max_commit_bytes: 128,
    }
}

#[test]
fn manifest_preserves_executable_mode_and_exact_paths() {
    let listing = record("100755", "blob", 3, "bin/tool");
    let (entries, _) = parse_tree_listing(&listing, limits(), false, 40).unwrap();
    assert_eq!(entries[0].mode, "100755");
    assert!(entries[0].executable());
    assert_eq!(entries[0].git_path, "bin/tool");
}

#[test]
fn manifest_rejects_symlinks_gitlinks_and_reserved_paths() {
    for listing in [
        record("120000", "blob", 3, "link"),
        record("160000", "commit", 3, "module"),
        record("100644", "blob", 3, "../escape"),
        record("100644", "blob", 3, ".git/config"),
        record("100644", "blob", 3, "dir\\escape"),
    ] {
        assert!(parse_tree_listing(&listing, limits(), false, 40).is_err());
    }
}

#[test]
fn manifest_rejects_duplicate_and_case_folded_collisions() {
    let mut duplicate = record("100644", "blob", 1, "same");
    duplicate.extend(record("100644", "blob", 1, "same"));
    assert!(parse_tree_listing(&duplicate, limits(), false, 40).is_err());
    let mut folded = record("100644", "blob", 1, "Readme");
    folded.extend(record("100644", "blob", 1, "README"));
    assert!(parse_tree_listing(&folded, limits(), true, 40).is_err());
    assert!(parse_tree_listing(&folded, limits(), false, 40).is_ok());

    let mut folded_parent = record("100644", "blob", 1, "Readme/one");
    folded_parent.extend(record("100644", "blob", 1, "README/two"));
    assert!(parse_tree_listing(&folded_parent, limits(), true, 40).is_err());
}

#[test]
fn manifest_rejects_file_directory_collisions() {
    let mut file_first = record("100644", "blob", 1, "same");
    file_first.extend(record("100644", "blob", 1, "same/child"));
    assert!(parse_tree_listing(&file_first, limits(), false, 40).is_err());

    let mut directory_first = record("100644", "blob", 1, "same/child");
    directory_first.extend(record("100644", "blob", 1, "same"));
    assert!(parse_tree_listing(&directory_first, limits(), false, 40).is_err());
}

#[test]
fn manifest_enforces_file_total_and_path_limits() {
    assert!(
        parse_tree_listing(&record("100644", "blob", 9, "large"), limits(), false, 40).is_err()
    );
    let mut total = record("100644", "blob", 7, "one");
    total.extend(record("100644", "blob", 7, "two"));
    assert!(parse_tree_listing(&total, limits(), false, 40).is_err());
    assert!(parse_tree_listing(
        &record("100644", "blob", 1, &"p".repeat(33)),
        limits(),
        false,
        40
    )
    .is_err());
}
