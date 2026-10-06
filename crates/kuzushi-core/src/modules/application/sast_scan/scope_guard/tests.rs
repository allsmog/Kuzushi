use super::*;

fn repository() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("service")).unwrap();
    std::fs::create_dir(root.path().join("other")).unwrap();
    std::fs::write(root.path().join("service/app.rs"), "fn main() {}\n").unwrap();
    root
}

fn prepare(root: &Path, input: Value) -> Result<Value> {
    let registry = ModuleRegistry::with_v2_builtins();
    let config = crate::V2Config::default();
    let workspace = crate::WorkspaceTarget::new(root)?;
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    Ok(registry
        .prepare_dispatch_input("sast:scan", input, &ctx, None)?
        .value()
        .clone())
}

#[test]
fn native_file_scope_cannot_publish_work_or_expand_to_its_parent() {
    let root = repository();
    let error = prepare(
        root.path(),
        json!({"taskMode":"manual", "tasks":["secret-scan", "cargo-audit"],
        "paths":["service/app.rs"]}),
    )
    .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("requires directory scopes"), "{error:#}");
    assert!(message.contains("cargo-audit"), "{error:#}");
    assert!(
        !message.contains("secret-scan"),
        "only directory-only engines are named: {error:#}"
    );
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
}

#[test]
fn exact_file_engines_bind_a_file_scope_without_widening() {
    let root = repository();
    let prepared = prepare(
        root.path(),
        json!({"taskMode":"manual", "tasks":["secret-scan"],
        "paths":["./service/app.rs"]}),
    )
    .unwrap();
    assert_eq!(prepared["paths"], json!(["service/app.rs"]));
    assert!(!root.path().join(".kuzushi/v3/runs").exists());
}

#[test]
fn canonical_directory_scope_is_bound_without_model_execution() {
    let root = repository();
    let prepared = prepare(
        root.path(),
        json!({"taskMode":"manual", "tasks":["secret-scan"],
        "paths":["./service/"]}),
    )
    .unwrap();
    assert_eq!(prepared["paths"], json!(["service"]));
    assert!(!root.path().join(".kuzushi/v3/runs").exists());
}

#[test]
fn automatic_scope_assessment_retains_declared_optional_tools_without_probing_them() {
    let selected = requested_scope_contracts(&json!({})).unwrap();
    assert!(selected.engine_ids.contains(&"semgrep"));
    assert!(selected.engine_ids.contains(&"cargo-audit"));
    let selected = requested_scope_contracts(&json!({"disabledTasks":["semgrep"]})).unwrap();
    assert!(!selected.engine_ids.contains(&"semgrep"));
    assert!(selected.engine_ids.contains(&"cargo-audit"));
}

#[test]
fn repository_only_engines_require_a_separate_whole_repository_plan() {
    let root = repository();
    for engine in ["offense-review", "systems-hunt"] {
        let input = json!({"taskMode":"manual", "tasks":[engine], "paths":["service"]});
        let error = prepare(root.path(), input).unwrap_err();
        assert!(
            error.to_string().contains("whole repository"),
            "{engine}: {error:#}"
        );
        prepare(root.path(), json!({"taskMode":"manual", "tasks":[engine]})).unwrap();
    }
}

#[test]
fn taint_scope_accepts_one_directory_and_refuses_wider_or_conflicting_input() {
    let root = repository();
    prepare(
        root.path(),
        json!({"tasks":["taint-iris-next"],"paths":["service"]}),
    )
    .unwrap();
    for paths in [json!(["service", "other"]), json!(["service/app.rs"])] {
        assert!(prepare(
            root.path(),
            json!({"tasks":["taint-iris-next"], "paths":paths})
        )
        .is_err());
    }
    let input = json!({"tasks":["taint-iris-next"],"paths":["service"],"targetSubdir":"other"});
    assert!(prepare(root.path(), input).is_err());
}

#[test]
fn agentic_file_scope_remains_exact_and_explicit_patterns_cannot_replace_it() {
    let root = repository();
    let prepared = prepare(
        root.path(),
        json!({"tasks":["agentic"],"paths":["service/app.rs"]}),
    )
    .unwrap();
    assert_eq!(prepared["paths"], json!(["service/app.rs"]));
    let error = bind_sast_scope_input(
        json!({"tasks":["agentic"],"paths":["service"],
        "includePatterns":["other/*"]}),
        root.path(),
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("cannot override an approved scope"),
        "{error:#}"
    );
    bind_sast_scope_input(
        json!({"tasks":["agentic"],"paths":["service"],
        "includePatterns":[]}),
        root.path(),
    )
    .unwrap();
}

#[cfg(unix)]
#[test]
fn scope_rejects_symlink_components_even_when_the_destination_is_inside_the_repository() {
    let root = repository();
    std::os::unix::fs::symlink(root.path().join("service"), root.path().join("alias")).unwrap();
    for path in ["alias", "alias/app.rs"] {
        let error = prepare(root.path(), json!({"tasks":["agentic"],"paths":[path]})).unwrap_err();
        assert!(format!("{error:#}").contains("symlink"), "{error:#}");
    }
}

#[test]
fn real_native_discovery_reads_selected_directory_and_persists_consumable_findings() {
    let root = repository();
    let token = format!("{}{}", "ghp_", "a".repeat(36));
    for scope in ["service", "other"] {
        std::fs::write(
            root.path().join(scope).join("credentials.js"),
            format!("const token = {token:?};\n"),
        )
        .unwrap();
    }
    let registry = ModuleRegistry::with_v2_builtins();
    let config = crate::V2Config::default();
    let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
    let store = crate::FindingStore::open(workspace.findings_db_path()).unwrap();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let prepared = registry
        .prepare_dispatch_input(
            "sast:scan",
            json!({"tasks":["secret-scan"],
        "paths":["service"], "runId":"scoped-native", "verify":false, "autoPatch":false}),
            &ctx,
            None,
        )
        .unwrap();
    let result = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    assert_eq!(
        crate::module_result::tool_result_status(&result),
        crate::ToolResultStatus::Completed
    );
    let findings = store.list_findings_for_scan_id("scoped-native").unwrap();
    assert!(
        !findings.is_empty(),
        "real scanner must supply findings to the next phase"
    );
    assert!(findings
        .iter()
        .all(|finding| finding.file_path == "service/credentials.js"));
}
