use super::*;

fn receipt(enumeration: ContextEnumeration) -> ContextSnapshotInspection {
    ContextSnapshotInspection {
        enumeration,
        entries: 3,
        max_entries: 100000,
        inspected_bytes: 42,
        max_inspected_bytes: 536870912,
        max_file_inspection_bytes: 262144,
        enumerated_files: 3,
        sampled_files: 1,
        omitted_paths: 2,
        truncated_files: 1,
        truncated: true,
    }
}

#[test]
fn receipts_disclose_exact_limits_and_git_scope_without_complete_coverage_claims() {
    let text = inspection_lines(Some(&receipt(ContextEnumeration::GitIndex))).join("\n");
    for expected in [
        "Git tracked files",
        "Untracked source is outside",
        "1 of 3",
        "3 / 100000",
        "42 / 536870912",
        "262144",
        "2 paths",
        "in part: 1",
        "Inventory: partial",
    ] {
        assert!(text.contains(expected), "{text}");
    }
    assert!(text.contains("does not establish full content coverage"));
    let text = inspection_lines(Some(&receipt(ContextEnumeration::Filesystem))).join("\n");
    assert!(text.contains("bounded filesystem inventory"));
    assert!(!text.contains("Untracked source is outside"));
}

#[test]
fn unknown_legacy_inspection_has_a_rebuild_action_and_no_invented_counts() {
    let text = inspection_lines(None).join("\n");
    assert!(text.contains("unknown") && text.contains("Rebuild context"));
    assert!(!text.contains("0 /"));
}

#[test]
fn interrupted_enumeration_never_claims_a_filesystem_fallback() {
    let mut value = receipt(ContextEnumeration::Interrupted);
    value.entries = 0;
    value.inspected_bytes = 0;
    value.enumerated_files = 0;
    value.sampled_files = 0;
    let text = inspection_lines(Some(&value)).join("\n");
    assert!(text.contains("canceled during Git path acquisition"));
    assert!(text.contains("No source files were inspected"));
    assert!(text.contains("Inventory: partial"));
    assert!(!text.contains("bounded filesystem inventory"));
}
