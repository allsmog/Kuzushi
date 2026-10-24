use super::*;
use crate::capabilities::threat_model::ThreatModelBuildRoots;
use crate::config::V2Config;

fn input(root: &Path, budget: usize) -> BuildInput {
    BuildInput {
        roots: ThreatModelBuildRoots {
            workspace_root: root.to_path_buf(),
            analysis_root: root.to_path_buf(),
            scope: None,
        },
        max_source_bytes: budget,
        context_limit: 200,
        ..Default::default()
    }
}

fn candidate(anchors: Vec<usize>) -> Candidate {
    Candidate {
        path: "lib.rs".to_string(),
        citation_path: "lib.rs".to_string(),
        language: "Rust".to_string(),
        anchors,
    }
}

fn context(config: &V2Config) -> ToolExecutionContext<'_> {
    ToolExecutionContext {
        config,
        workspace: None,
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    }
}

#[test]
fn source_code_child_scope_keeps_workspace_citations_and_prioritizes_selected_boundaries() {
    let target = tempfile::tempdir().unwrap();
    let scope = target.path().join("packages/api");
    std::fs::create_dir_all(&scope).unwrap();
    std::fs::write(scope.join("aaa.rs"), "fn unrelated() {}\n").unwrap();
    std::fs::write(scope.join("lib.rs"), "fn selected() {}\n").unwrap();
    let mut input = input(target.path(), 4000);
    input.roots.analysis_root = scope.clone();
    input.context_limit = 1;
    let surface: AttackSurface = serde_json::from_value(serde_json::json!({
        "id":"AS-selected", "kind":"deserialization_point", "path":"packages/api/lib.rs",
        "line":1, "language":"Rust", "title":"selected", "evidence":"selected()"
    }))
    .unwrap();
    let config = V2Config::default();
    let source = collect_source_code(&input, &[surface], None, &context(&config)).unwrap();
    let body: serde_json::Value = serde_json::from_str(&source.content).unwrap();
    assert_eq!(body["scopePath"], "packages/api");
    assert_eq!(body["files"][0]["path"], "packages/api/lib.rs");
    assert!(source.references.contains("packages/api/lib.rs:1"));
    assert!(!source.references.contains("lib.rs:1"));
    assert!(!source.content.contains("unrelated"));
    assert!(source.partial);
}

#[test]
fn source_code_read_limits_and_invalid_text_are_disclosed() {
    let target = tempfile::tempdir().unwrap();
    std::fs::write(target.path().join("lib.rs"), "fn allowed() {}\n").unwrap();
    let input = input(target.path(), 4000);
    let inventory = crate::repository_inventory::build_repository_inventory(target.path()).unwrap();
    let selected = selection::select_files(&input, &inventory, &[]).unwrap();
    let mut report = new_report(&input, "tree".into(), &selected);
    report.read_bytes = MAX_READ_BYTES;
    assert!(
        read_code_file(target.path(), &candidate(vec![]), &mut report)
            .unwrap()
            .is_none()
    );
    assert_eq!(report.omissions["source read ceiling"], 1);
    report.read_bytes = 0;
    std::fs::write(target.path().join("lib.rs"), vec![b'x'; MAX_FILE_BYTES + 1]).unwrap();
    assert!(
        read_code_file(target.path(), &candidate(vec![]), &mut report)
            .unwrap()
            .is_none()
    );
    assert_eq!(report.omissions["source read ceiling"], 2);
    assert!(decode_source(vec![0, 1], &mut report).unwrap().is_none());
    assert!(decode_source(vec![255], &mut report).unwrap().is_none());
    assert_eq!(report.omissions["binary source"], 1);
    assert_eq!(report.omissions["non-UTF-8 source"], 1);
    assert!(report.partial());
}

#[cfg(unix)]
#[test]
fn source_code_rejects_a_selected_file_replaced_with_an_external_symlink() {
    let target = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    std::fs::write(target.path().join("lib.rs"), "fn allowed() {}\n").unwrap();
    std::fs::write(external.path().join("secret.rs"), "EXTERNAL_MARKER").unwrap();
    let input = input(target.path(), 4000);
    let inventory = crate::repository_inventory::build_repository_inventory(target.path()).unwrap();
    let selected = selection::select_files(&input, &inventory, &[]).unwrap();
    let mut report = new_report(&input, "tree".into(), &selected);
    std::fs::remove_file(target.path().join("lib.rs")).unwrap();
    std::os::unix::fs::symlink(
        external.path().join("secret.rs"),
        target.path().join("lib.rs"),
    )
    .unwrap();
    let error = read_code_file(target.path(), &candidate(vec![]), &mut report).unwrap_err();
    assert!(error.to_string().contains("no longer a regular file"));
    assert_eq!(report.read_bytes, 0);
    assert!(report.files.is_empty());
}

#[test]
fn source_code_honors_operator_cancellation_before_collection() {
    let target = tempfile::tempdir().unwrap();
    let config = V2Config::default();
    let cancellation = crate::scan::ScanCancellation::default();
    cancellation.cancel();
    let mut ctx = context(&config);
    ctx.cancellation = Some(&cancellation);
    let error = collect_source_code(&input(target.path(), 4000), &[], None, &ctx)
        .err()
        .unwrap();
    assert!(error.to_string().contains("collection cancelled"));
}

#[test]
fn source_code_keeps_complete_small_files_with_hashes_and_original_line_refs() {
    let raw = "pub fn policy() -> bool { true }\n#[cfg(test)] mod tests { fn example() {} }\n";
    let file = excerpts::excerpt(&candidate(Vec::new()), raw, 4_000)
        .unwrap()
        .unwrap();
    assert_eq!(file.file_sha256, crate::options::prompt_content_sha256(raw));
    assert_eq!(file.lines.len(), 1);
    assert_eq!(file.lines[0].reference, "lib.rs:1");
    assert!(file.lines[0].text.contains("pub fn policy"));
    assert_eq!(file.excluded_test_lines, 1);
    assert_eq!(file.omitted_lines, 0);
}

#[test]
fn source_code_prioritizes_late_selected_boundaries_instead_of_file_headers() {
    let mut lines: Vec<_> = (0..1_000)
        .map(|n| format!("let value_{n} = {n};"))
        .collect();
    lines[900] = "serde_json::from_str::<Request>(untrusted_input);".to_string();
    let file = excerpts::excerpt(&candidate(vec![900]), &lines.join("\n"), 2_500)
        .unwrap()
        .unwrap();
    assert!(file
        .lines
        .iter()
        .any(|line| line.reference == "lib.rs:901" && line.text.contains("untrusted_input")));
    assert!(file.lines.iter().any(|line| line.reference == "lib.rs:900"));
    assert!(file.omitted_lines > 900);
    assert!(serde_json::to_vec(&file).unwrap().len() <= 2_500);
}

#[test]
fn source_code_serialized_excerpts_respect_budget_with_unicode_and_escaping() {
    let raw = (0..150)
        .map(|i| format!("let text_{i} = \"é界\\\\\\\"quoted\";"))
        .collect::<Vec<_>>()
        .join("\n");
    for budget in [256, 500, 1024, 4000] {
        if let Some(file) = excerpts::excerpt(&candidate(vec![80]), &raw, budget).unwrap() {
            assert!(serde_json::to_vec(&file).unwrap().len() <= budget);
            assert!(file.lines.iter().all(|line| line.text.contains("é界")));
        }
    }
}

#[test]
fn source_code_small_target_is_attached_with_actual_tree_identity() {
    let target = tempfile::tempdir().unwrap();
    std::fs::write(
        target.path().join("lib.rs"),
        "pub fn shared_contract() -> bool { true }\n",
    )
    .unwrap();
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: None,
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let source = collect_source_code(&input(target.path(), 4000), &[], None, &ctx).unwrap();
    let body: serde_json::Value = serde_json::from_str(&source.content).unwrap();
    assert_eq!(body["eligibleFiles"], 1);
    assert_eq!(body["treeHash"], current_tree_hash(target.path()).unwrap());
    assert!(source.content.contains("shared_contract"));
    assert!(source.references.contains("lib.rs:1"));
    assert!(!source.partial);
    assert!(source.content.len() <= 4000);
}

#[test]
fn source_code_refuses_old_grounding_and_impossibly_small_budgets() {
    let target = tempfile::tempdir().unwrap();
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: None,
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let mismatch = collect_source_code(&input(target.path(), 4000), &[], Some("old-tree"), &ctx)
        .err()
        .unwrap();
    assert!(mismatch
        .to_string()
        .contains("differ from grounded context"));
    let tiny = collect_source_code(&input(target.path(), 1), &[], None, &ctx)
        .err()
        .unwrap();
    assert!(tiny.to_string().contains("maxSourceBytes >= 1024"));
}

#[test]
fn source_code_selection_balances_components() {
    let target = tempfile::tempdir().unwrap();
    for group in ["services/a", "services/b", "services/c"] {
        std::fs::create_dir_all(target.path().join(group)).unwrap();
        for n in 0..5 {
            std::fs::write(
                target.path().join(group).join(format!("file{n}.rs")),
                "fn item() {}\n",
            )
            .unwrap();
        }
    }
    let mut input = input(target.path(), 4000);
    input.context_limit = 3;
    let inventory = crate::repository_inventory::build_repository_inventory(target.path()).unwrap();
    let selected = selection::select_files(&input, &inventory, &[]).unwrap();
    assert_eq!(selected.eligible, 15);
    assert_eq!(
        selected
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>(),
        [
            "services/a/file0.rs",
            "services/b/file0.rs",
            "services/c/file0.rs"
        ]
    );
}

#[test]
fn complete_enumeration_survives_a_large_unselected_lockfile() {
    let target = tempfile::tempdir().unwrap();
    std::fs::write(
        target.path().join("lib.rs"),
        "// Owned source text. Never executed.\n",
    )
    .unwrap();
    std::fs::write(
        target.path().join("Cargo.lock"),
        "# Owned lockfile comment.\n".repeat(14_000),
    )
    .unwrap();
    let config = V2Config::default();
    let source =
        collect_source_code(&input(target.path(), 4096), &[], None, &context(&config)).unwrap();
    let body: serde_json::Value = serde_json::from_str(&source.content).unwrap();
    assert_eq!(body["files"].as_array().unwrap().len(), 1);
    assert_eq!(body["files"][0]["path"], "lib.rs");
    assert!(!source.content.contains("Owned lockfile comment"));
}

#[test]
fn incomplete_or_unknown_enumeration_is_still_refused() {
    let root = tempfile::tempdir().unwrap();
    let mut inventory =
        crate::repository_inventory::build_repository_inventory(root.path()).unwrap();
    for complete in [Some(false), None] {
        inventory.inspection.as_mut().unwrap().enumeration_complete = complete;
        assert!(require_complete_enumeration(&inventory)
            .unwrap_err()
            .to_string()
            .contains("complete filename enumeration"));
    }
}
