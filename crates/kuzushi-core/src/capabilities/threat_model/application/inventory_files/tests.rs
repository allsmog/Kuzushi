use super::*;

#[test]
fn prompt_inventory_uses_repository_ignore_membership() {
    let root = tempfile::tempdir().unwrap();
    assert!(std::process::Command::new("git")
        .args(["init", "--quiet"])
        .arg(root.path())
        .status()
        .unwrap()
        .success());
    fs::write(root.path().join(".gitignore"), "ignored-note.txt\n").unwrap();
    fs::write(
        root.path().join("ignored-note.txt"),
        "Owned ignored text. Never executed.",
    )
    .unwrap();
    fs::write(
        root.path().join("owned.rs"),
        "// Owned source text. Never executed.\n",
    )
    .unwrap();
    assert!(std::process::Command::new("git")
        .arg("-C")
        .arg(root.path())
        .args(["add", ".gitignore", "owned.rs"])
        .status()
        .unwrap()
        .success());
    let config = crate::V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: None,
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let files = PromptRepositoryInventory::collect(root.path(), 40, &ctx)
        .unwrap()
        .files;
    assert!(files.iter().any(|path| path == "owned.rs"));
    assert!(
        !files.iter().any(|path| path == "ignored-note.txt"),
        "{files:?}"
    );
}

fn context<'a>(
    config: &'a crate::V2Config,
    cancellation: Option<&'a crate::scan::ScanCancellation>,
) -> ToolExecutionContext<'a> {
    ToolExecutionContext {
        config,
        workspace: None,
        findings_store: None,
        trace: None,
        cancellation,
        authorization: Default::default(),
    }
}

#[test]
fn a_bounded_filename_list_discloses_the_denominator_and_keeps_loose_root_files() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("a")).unwrap();
    for name in ["a/first.rs", "a/second.rs", "loose.rs"] {
        fs::write(root.path().join(name), "// Owned source text.").unwrap();
    }
    let config = crate::V2Config::default();
    let inventory =
        PromptRepositoryInventory::collect(root.path(), 1, &context(&config, None)).unwrap();
    assert_eq!(inventory.files, ["loose.rs"]);
    assert_eq!(inventory.receipt["enumerationComplete"], true);
    assert_eq!(inventory.receipt["enumeratedFiles"], 3);
    assert_eq!(inventory.receipt["unlistedFiles"], 2);
    assert_eq!(inventory.receipt["completeRepositoryCoverage"], false);
    assert!(inventory.disclosure().contains("1 / 3 enumerated paths"));
}

#[test]
fn incomplete_enumeration_does_not_rename_known_members_as_a_complete_repository() {
    let root = tempfile::tempdir().unwrap();
    for n in 0..8 {
        fs::write(root.path().join(format!("{n}.rs")), "// Owned source text.").unwrap();
    }
    let source = crate::workspace::inventory::build_repository_inventory_with_limits(
        root.path(),
        3,
        1024,
        &mut |_| {},
        &|| false,
    )
    .unwrap();
    let inventory = PromptRepositoryInventory::from_inventory(source, 40).unwrap();
    assert_eq!(inventory.receipt["enumerationComplete"], false);
    assert!(inventory.receipt["truncation"]["reason"].is_string());
    assert_eq!(inventory.receipt["completeRepositoryCoverage"], false);
    assert!(inventory.disclosure().contains("enumeration partial"));
}

#[test]
fn partial_content_inspection_is_distinct_from_partial_filename_enumeration() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("large.rs"), vec![b' '; 300_000]).unwrap();
    let config = crate::V2Config::default();
    let inventory =
        PromptRepositoryInventory::collect(root.path(), 40, &context(&config, None)).unwrap();
    assert_eq!(inventory.receipt["enumerationComplete"], true);
    assert_eq!(inventory.receipt["truncatedFileCount"], 1);
    assert_eq!(inventory.receipt["maxEntries"], 100_000);
    assert_eq!(inventory.receipt["maxInspectedBytes"], 512 * 1024 * 1024);
    assert_eq!(inventory.receipt["maxFileInspectionBytes"], 256 * 1024);
    assert_eq!(inventory.receipt["completeRepositoryCoverage"], false);
}

#[test]
fn cancellation_is_checked_before_opening_the_repository() {
    let root = tempfile::tempdir().unwrap();
    let config = crate::V2Config::default();
    let cancellation = crate::scan::ScanCancellation::default();
    cancellation.cancel();
    let error = PromptRepositoryInventory::collect(
        &root.path().join("absent"),
        40,
        &context(&config, Some(&cancellation)),
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("preparation canceled"),
        "{error}"
    );
}

#[test]
fn prepared_literal_membership_is_reused_without_a_second_directory_walk() {
    let root = tempfile::tempdir().unwrap();
    let name = " literal\nname-東京.rs";
    fs::write(root.path().join(name), "// Owned source text.").unwrap();
    let config = crate::V2Config::default();
    let inventory =
        PromptRepositoryInventory::collect(root.path(), 40, &context(&config, None)).unwrap();
    let before = inventory.prompt_data().unwrap();
    fs::write(root.path().join("later.rs"), "// Later source text.").unwrap();
    assert_eq!(inventory.prompt_data().unwrap(), before);
    let prompt: Value = serde_json::from_str(&before).unwrap();
    assert_eq!(prompt["listedPaths"], json!([name]));
    assert_eq!(
        prompt["listedPathsSha256"],
        crate::options::prompt_content_sha256(&serde_json::to_string(&vec![name]).unwrap())
    );
}

#[test]
fn oversized_path_lists_fail_before_any_model_request() {
    let root = tempfile::tempdir().unwrap();
    let mut source = crate::repository_inventory::build_repository_inventory(root.path()).unwrap();
    source.inspection.as_mut().unwrap().files = (0..3000)
        .map(|n| format!("{n}-{}.rs", "x".repeat(240)))
        .collect();
    let error = PromptRepositoryInventory::from_inventory(source, 3000).unwrap_err();
    assert!(error.to_string().contains("exceeds 512 KiB"), "{error}");
}

#[cfg(unix)]
#[test]
fn symlink_cycles_and_external_directories_are_excluded() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(
        outside.path().join("outside.rs"),
        "// Owned external fixture text.",
    )
    .unwrap();
    std::os::unix::fs::symlink(root.path(), root.path().join("cycle")).unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join("external")).unwrap();
    fs::write(root.path().join("owned.rs"), "// Owned source text.").unwrap();
    let config = crate::V2Config::default();
    let inventory =
        PromptRepositoryInventory::collect(root.path(), 40, &context(&config, None)).unwrap();
    assert_eq!(inventory.files, ["owned.rs"]);
}
