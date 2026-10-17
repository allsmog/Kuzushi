use super::*;
use std::fs;
const MAX_SOURCE_FILES: usize = 6000;
const MAX_FILE_BYTES: usize = 256 * 1024;
const LIMITS: SourcePrefixLimits = SourcePrefixLimits {
    max_files: MAX_SOURCE_FILES,
    max_bytes: 16 * 1024 * 1024,
    max_file_bytes: MAX_FILE_BYTES,
};
fn selected(path: &str) -> bool {
    path.ends_with(".rs") || path.ends_with(".md")
}
fn collect(
    root: &Path,
    progress: &mut dyn FnMut(usize),
    canceled: &dyn Fn() -> bool,
) -> Result<SourcePrefixes> {
    collect_source_prefixes(root, LIMITS, &selected, progress, canceled)
}
fn index_inventory(
    root: &Path,
    inventory: RepositoryInventory,
    canceled: &dyn Fn() -> bool,
) -> Result<SourcePrefixes> {
    index_source_prefixes(root, inventory, LIMITS, &selected, canceled)
}

fn inventory_with_paths(root: &Path, paths: &[&str]) -> RepositoryInventory {
    let mut inventory = crate::workspace::build_repository_inventory(root).unwrap();
    inventory.inspection.as_mut().unwrap().files =
        paths.iter().map(|path| (*path).into()).collect();
    inventory
}

#[test]
fn indexes_loose_parent_files_and_discloses_nonselected_files() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("src")).unwrap();
    fs::write(
        root.path().join("src/child.rs"),
        "// Owned child context.\n",
    )
    .unwrap();
    fs::write(root.path().join("README.md"), "Owned parent context\n").unwrap();
    fs::write(root.path().join("ignored.bin"), [0, 1]).unwrap();
    let index = collect(root.path(), &mut |_| {}, &|| false).unwrap();
    assert_eq!(
        index
            .files
            .iter()
            .map(|row| row.relative.as_str())
            .collect::<Vec<_>>(),
        ["README.md", "src/child.rs"]
    );
    assert_eq!(index.coverage["omittedSourceFiles"], 1);
    assert_eq!(index.coverage["completeRepositoryCoverage"], false);
}

#[cfg(unix)]
#[test]
fn source_inventory_skips_symlink_cycles_and_refuses_an_injected_link() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(root.path().join("safe.rs"), "// Owned source\n").unwrap();
    fs::write(
        outside.path().join("secret.rs"),
        "OUTSIDE_THREAT_LEAD_TOKEN",
    )
    .unwrap();
    symlink(root.path(), root.path().join("cycle")).unwrap();
    symlink(
        outside.path().join("secret.rs"),
        root.path().join("linked.rs"),
    )
    .unwrap();
    let inventory = inventory_with_paths(root.path(), &["safe.rs", "linked.rs"]);
    let index = index_inventory(root.path(), inventory, &|| false).unwrap();
    assert_eq!(index.files.len(), 1);
    assert!(!index.files[0].text.contains("OUTSIDE_THREAT_LEAD_TOKEN"));
    assert_eq!(index.coverage["status"], "partial");
    assert_eq!(index.coverage["omittedSourceFiles"], 1);
}

#[test]
fn source_prefixes_and_inventory_share_the_combined_byte_ceiling() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("owned.rs"), "// Owned source prefix\n").unwrap();
    let mut inventory = inventory_with_paths(root.path(), &["owned.rs"]);
    inventory.inspection.as_mut().unwrap().inspected_bytes =
        crate::workspace::inventory::MAX_REPOSITORY_INSPECTED_BYTES - 4;
    let index = index_inventory(root.path(), inventory, &|| false).unwrap();
    assert_eq!(index.files[0].text.as_bytes().len(), 4);
    assert_eq!(index.coverage["reservedSourceBytes"], 4);
    assert_eq!(index.coverage["maxSourceBytes"], 4);
    assert_eq!(index.coverage["status"], "partial");
}

#[test]
fn failed_read_retains_its_reservation_and_cannot_expand_the_budget() {
    let root = tempfile::tempdir().unwrap();
    let mut inventory = inventory_with_paths(root.path(), &["missing.rs", "later.rs"]);
    inventory.inspection.as_mut().unwrap().inspected_bytes =
        crate::workspace::inventory::MAX_REPOSITORY_INSPECTED_BYTES - 4;
    let index = index_inventory(root.path(), inventory, &|| false).unwrap();
    assert!(index.files.is_empty());
    assert_eq!(index.coverage["reservedSourceBytes"], 4);
    assert_eq!(index.coverage["inspectedSourceBytes"], 0);
    assert_eq!(index.coverage["attemptedFiles"], 1);
    assert_eq!(index.coverage["omittedSourceFiles"], 2);
}

#[test]
fn byte_and_file_limits_bound_path_disclosures() {
    let root = tempfile::tempdir().unwrap();
    let mut inventory = inventory_with_paths(root.path(), &[]);
    let inspection = inventory.inspection.as_mut().unwrap();
    inspection.inspected_bytes = crate::workspace::inventory::MAX_REPOSITORY_INSPECTED_BYTES;
    inspection.files = (0..200).map(|i| format!("owned-{i}.rs")).collect();
    let index = index_inventory(root.path(), inventory, &|| false).unwrap();
    assert!(index.files.is_empty());
    assert_eq!(index.coverage["omittedSourceFiles"], 200);
    assert_eq!(index.coverage["omissions"].as_array().unwrap().len(), 128);
    assert_eq!(index.coverage["additionalOmissions"], 72);
}

#[test]
fn canceling_source_inventory_does_not_return_a_complete_index() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("owned.rs"), "// Owned context\n").unwrap();
    let error = collect(root.path(), &mut |_| {}, &|| true).err().unwrap();
    assert!(error.to_string().contains("canceled"), "{error:#}");
}

#[test]
fn full_per_file_prefix_is_disclosed_without_unbounded_reads() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("owned.rs"),
        vec![b'a'; MAX_FILE_BYTES + 100],
    )
    .unwrap();
    let index = collect(root.path(), &mut |_| {}, &|| false).unwrap();
    assert_eq!(index.files[0].text.len(), MAX_FILE_BYTES);
    assert_eq!(index.coverage["truncatedSourceFiles"], 1);
    assert_eq!(index.coverage["status"], "partial");
}

#[test]
fn deep_tree_is_enumerated_without_a_second_recursive_walk() {
    let root = tempfile::tempdir().unwrap();
    let mut folder = root.path().to_path_buf();
    for _ in 0..80 {
        folder = folder.join("d");
        fs::create_dir(&folder).unwrap();
    }
    fs::write(folder.join("owned.rs"), "// Owned deep context\n").unwrap();
    let index = collect(root.path(), &mut |_| {}, &|| false).unwrap();
    assert_eq!(index.files.len(), 1);
    assert!(index.files[0].relative.ends_with("owned.rs"));
}

#[test]
fn empty_successful_files_still_obey_the_source_file_limit() {
    let root = tempfile::tempdir().unwrap();
    let inventory = inventory_with_paths(root.path(), &[]);
    let mut coverage = SourceCoverage::new(&inventory, LIMITS);
    for _ in 0..MAX_SOURCE_FILES {
        let reserved = coverage.next_file_limit("empty.rs").unwrap();
        coverage.record_bytes("empty.rs", 0, false, reserved);
    }
    assert!(coverage.next_file_limit("extra.rs").is_none());
    let receipt = coverage.receipt(&inventory);
    assert_eq!(receipt["attemptedFiles"], MAX_SOURCE_FILES);
    assert_eq!(receipt["reservedSourceBytes"], 0);
    assert_eq!(receipt["omittedSourceFiles"], 1);
}

#[test]
fn invalid_limits_fail_before_inventory_or_source_io() {
    let root = Path::new("/missing-owned-prefix-fixture");
    for limits in [
        SourcePrefixLimits {
            max_files: 0,
            ..LIMITS
        },
        SourcePrefixLimits {
            max_bytes: 0,
            ..LIMITS
        },
        SourcePrefixLimits {
            max_file_bytes: 0,
            ..LIMITS
        },
        SourcePrefixLimits {
            max_file_bytes: 256 * 1024 + 1,
            ..LIMITS
        },
    ] {
        let error = collect_source_prefixes(root, limits, &selected, &mut |_| {}, &|| false)
            .err()
            .unwrap();
        assert!(error.to_string().contains("limit is invalid"), "{error:#}");
    }
}

#[test]
fn supplied_prefix_limits_are_enforced_before_reads_and_reported_exactly() {
    let root = tempfile::tempdir().unwrap();
    for name in ["a.rs", "b.rs", "c.rs"] {
        fs::write(root.path().join(name), "owned input").unwrap();
    }
    let inventory = inventory_with_paths(root.path(), &["a.rs", "b.rs", "c.rs"]);
    let index = index_source_prefixes(
        root.path(),
        inventory,
        SourcePrefixLimits {
            max_files: 2,
            max_bytes: 7,
            max_file_bytes: 4,
        },
        &selected,
        &|| false,
    )
    .unwrap();
    assert_eq!(index.files.len(), 2);
    assert_eq!(index.files[0].text, "owne");
    assert_eq!(index.files[1].text, "own");
    assert_eq!(index.coverage["reservedSourceBytes"], 7);
    assert_eq!(index.coverage["inspectedSourceBytes"], 7);
    assert_eq!(index.coverage["omittedSourceFiles"], 1);
    assert_eq!(index.coverage["maxSourceFiles"], 2);
}

#[test]
fn source_prefix_exact_limit_is_not_truncation() {
    let root = tempfile::tempdir().unwrap();
    let bytes = b"// parser\n";
    fs::write(root.path().join("owned.rs"), bytes).unwrap();
    let inventory = inventory_with_paths(root.path(), &["owned.rs"]);
    let limits = SourcePrefixLimits {
        max_files: 1,
        max_bytes: bytes.len(),
        max_file_bytes: bytes.len(),
    };
    let output =
        index_source_prefixes(root.path(), inventory, limits, &selected, &|| false).unwrap();
    assert_eq!(output.files[0].text.as_bytes(), bytes);
    assert_eq!(output.coverage["truncatedSourceFiles"], 0);
    assert_eq!(output.coverage["status"], "bounded");
}

#[test]
fn source_prefix_never_invents_replacement_characters_at_a_utf8_boundary() {
    let root = tempfile::tempdir().unwrap();
    let prefix = "// parser ";
    fs::write(root.path().join("owned.rs"), format!("{prefix}🙂 guard\n")).unwrap();
    let inventory = inventory_with_paths(root.path(), &["owned.rs"]);
    let limit = prefix.len() + 2;
    let limits = SourcePrefixLimits {
        max_files: 1,
        max_bytes: limit,
        max_file_bytes: limit,
    };
    let output =
        index_source_prefixes(root.path(), inventory, limits, &selected, &|| false).unwrap();
    assert_eq!(output.files[0].text, prefix);
    assert_eq!(output.coverage["inspectedSourceBytes"], limit);
    assert_eq!(output.coverage["truncatedSourceFiles"], 1);
    assert_eq!(output.coverage["includedSourceTextBytes"], prefix.len());
    assert_eq!(output.coverage["incompleteUtf8PrefixBytes"], 2);
}

#[test]
fn source_prefix_omits_invalid_utf8_instead_of_fabricating_source() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("owned.rs"), b"// parser \xff guard\n").unwrap();
    let inventory = inventory_with_paths(root.path(), &["owned.rs"]);
    let output = index_inventory(root.path(), inventory, &|| false).unwrap();
    assert!(output.files.is_empty());
    assert_eq!(output.coverage["status"], "partial");
    assert_eq!(output.coverage["omittedSourceFiles"], 1);
}

#[test]
fn source_prefix_preserves_literal_replacement_character() {
    assert_eq!(
        decode_source_prefix("// �\n".as_bytes(), false).unwrap(),
        "// �\n"
    );
}

#[test]
fn incomplete_utf8_at_actual_eof_is_not_a_valid_source_prefix() {
    assert!(decode_source_prefix(b"// \xf0\x9f", false).is_err());
    assert!(decode_source_prefix(b"// \xffx", true).is_err());
}
