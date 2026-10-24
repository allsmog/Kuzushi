use super::*;
use std::path::Path;

fn write_scope_manifest(root: &Path, paths: &[&str]) {
    std::fs::create_dir_all(root.join(".kuzushi")).unwrap();
    let manifest = json!({"shards":{"fixture":{"paths":paths}}});
    std::fs::write(
        root.join(".kuzushi/shards.toml"),
        toml::to_string(&manifest).unwrap(),
    )
    .unwrap();
}

fn scope_input(id: &str) -> Value {
    json!({"campaignId":id,"tool":"full-mode:hunt","seasonPrompts":false})
}

#[test]
fn scope_file_plan_refuses_parent_paths_before_writing_artifacts() {
    let owned = tempdir().unwrap();
    let root = owned.path().join("repository");
    write_scope_manifest(&root, &["../outside.txt"]);
    std::fs::write(owned.path().join("outside.txt"), "owned inert fixture\n").unwrap();

    let error = run_plan(&root, scope_input("outside")).unwrap_err();

    assert!(
        error.to_string().contains("repository-relative"),
        "{error:#}"
    );
    assert!(!root
        .join(".kuzushi/v3/campaigns/outside/plan.json")
        .exists());
    assert!(!root.join(".kuzushi/v3/campaigns/outside/scope").exists());
}

#[test]
fn canceled_scope_file_plan_writes_no_plan_or_scope() {
    let root = tempdir().unwrap();
    write_scope_manifest(root.path(), &["."]);
    std::fs::write(root.path().join("README.txt"), "owned fixture\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let cancellation = crate::ScanCancellation::default();
    cancellation.cancel();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: Some(&cancellation),
        authorization: Default::default(),
    };

    let error = execute_campaign_plan(&scope_input("canceled"), &ctx).unwrap_err();

    assert!(error.to_string().contains("canceled"), "{error:#}");
    assert!(!root.path().join(".kuzushi/v3/campaigns/canceled").exists());
}

#[cfg(unix)]
#[test]
fn scope_file_plan_refuses_ambiguous_newline_file_names() {
    let root = tempdir().unwrap();
    write_scope_manifest(root.path(), &["."]);
    std::fs::write(root.path().join("one\ntwo.txt"), "owned fixture\n").unwrap();

    let error = run_plan(root.path(), scope_input("newline")).unwrap_err();

    assert!(error.to_string().contains("line-delimited"), "{error:#}");
    assert!(!root
        .path()
        .join(".kuzushi/v3/campaigns/newline/plan.json")
        .exists());
}

#[cfg(unix)]
#[test]
fn bounded_scope_keeps_root_files_and_excludes_directory_symlinks() {
    let owned = tempdir().unwrap();
    let root = owned.path().join("repository");
    write_scope_manifest(&root, &[".", "src"]);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("loose.rs"), "// root fixture\n").unwrap();
    std::fs::write(root.join("src/owned.rs"), "// nested fixture\n").unwrap();
    std::fs::write(owned.path().join("external.rs"), "// external fixture\n").unwrap();
    std::os::unix::fs::symlink(root.join("src"), root.join("src/cycle")).unwrap();
    std::os::unix::fs::symlink(owned.path().join("external.rs"), root.join("external.rs")).unwrap();

    let result = run_plan(&root, scope_input("bounded")).unwrap();
    let plan = &result["data"]["plan"];
    let scope = plan["jobs"][0]["input"]["scopeFile"].as_str().unwrap();
    let text = std::fs::read_to_string(root.join(scope)).unwrap();
    let lines = text
        .lines()
        .map(std::path::PathBuf::from)
        .collect::<Vec<_>>();

    assert!(lines.contains(&"loose.rs".into()));
    assert!(lines.contains(&"src/owned.rs".into()));
    assert!(!lines.contains(&"external.rs".into()));
    assert!(!lines
        .iter()
        .any(|path| path.to_string_lossy().contains("cycle")));
    assert_eq!(
        lines.len(),
        lines
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    );
    let receipt = &plan["scopeInventory"];
    let bytes = std::fs::read(root.join(receipt["path"].as_str().unwrap())).unwrap();
    assert_eq!(
        receipt["sha256"],
        crate::worker_protocol::sha256_digest(&bytes).0
    );
    assert_eq!(receipt["enumerationComplete"], true);
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("does not establish complete repository analysis"));
}

#[test]
fn prepared_campaign_dispatch_keeps_literal_scope_paths_and_no_map_result() {
    let root = tempdir().unwrap();
    let name = " literal directory ";
    write_scope_manifest(root.path(), &[name]);
    std::fs::create_dir_all(root.path().join(name)).unwrap();
    let file = format!("{name}/ loose file.rs ");
    std::fs::write(root.path().join(&file), "// literal owned fixture\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = crate::modules::ModuleRegistry::with_v2_builtins();
    let prepared = registry
        .prepare_dispatch_input("campaign:plan", scope_input("literal"), &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    let result = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    let plan = &result["data"]["plan"];
    let input = &plan["jobs"][0]["input"];
    let path = root.path().join(input["scopeFile"].as_str().unwrap());
    let output = result["output"].as_str().unwrap();

    assert!(output.starts_with("Compatibility draft only\n"));
    assert!(output.find("No jobs started").unwrap() < output.find("Target plan:").unwrap());
    assert!(!output.contains(root.path().to_string_lossy().as_ref()));
    let summary = result["summary"].as_str().unwrap();
    assert!(summary.contains("no jobs started"));
    assert!(!summary.contains('\n') && summary.len() <= 120);
    assert_ne!(summary, output);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), format!("{file}\n"));
    assert!(registry
        .prepare_dispatch_input("full-mode:hunt", input.clone(), &ctx, None)
        .is_ok());
    let descriptor = registry
        .catalog_tools_with_modules()
        .find(|(_, tool)| tool.name == "campaign:plan")
        .unwrap()
        .1;
    assert!(!descriptor.phase_result);
    assert!(!root
        .path()
        .join(".kuzushi/v3/campaigns/literal/queue.json")
        .exists());
}

#[test]
fn unsupported_child_options_refuse_before_publishing_a_plan() {
    let root = tempdir().unwrap();
    write_scope_manifest(root.path(), &["."]);
    std::fs::write(root.path().join("owned.rs"), "// owned fixture\n").unwrap();
    let input = json!({"campaignId":"standard","tool":"agentic-sast:scan","seasonPrompts":false});

    let error = run_plan(root.path(), input).unwrap_err();

    assert!(
        format!("{error:#}").contains("requires strategy=chunked"),
        "{error:#}"
    );
    assert!(!root
        .path()
        .join(".kuzushi/v3/campaigns/standard/plan.json")
        .exists());
}

#[test]
fn reused_campaign_id_preserves_its_plan_and_scope_receipt() {
    let root = tempdir().unwrap();
    write_scope_manifest(root.path(), &["."]);
    std::fs::write(root.path().join("owned.rs"), "// first source\n").unwrap();
    let result = run_plan(root.path(), scope_input("saved")).unwrap();
    let files = [
        ".kuzushi/v3/campaigns/saved/plan.json",
        result["data"]["plan"]["scopeInventory"]["path"]
            .as_str()
            .unwrap(),
        result["data"]["plan"]["jobs"][0]["input"]["scopeFile"]
            .as_str()
            .unwrap(),
    ];
    let before = files.map(|path| std::fs::read(root.path().join(path)).unwrap());
    std::fs::write(root.path().join("owned.rs"), "// changed source\n").unwrap();

    let error = run_plan(root.path(), scope_input("saved")).unwrap_err();

    assert!(
        error.to_string().contains("use a new campaignId"),
        "{error:#}"
    );
    assert_eq!(
        files.map(|path| std::fs::read(root.path().join(path)).unwrap()),
        before
    );
}

#[test]
fn concurrent_legacy_planners_publish_only_one_plan_for_an_id() {
    let root = tempdir().unwrap();
    write_scope_manifest(root.path(), &["."]);
    std::fs::write(
        root.path().join("owned.rs"),
        "// concurrent owned fixture\n",
    )
    .unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let threads = (0..2)
        .map(|_| {
            let path = root.path().to_path_buf();
            let start = barrier.clone();
            std::thread::spawn(move || {
                start.wait();
                run_plan(&path, scope_input("one")).map_err(|error| error.to_string())
            })
        })
        .collect::<Vec<_>>();
    let results = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(results
        .iter()
        .filter_map(|result| result.as_ref().err())
        .all(|error| error.contains("already has a plan")));
    let plan = read_json_file(&campaign_plan_path(root.path(), "one")).unwrap();
    assert_eq!(plan["jobCount"], 1);
    assert!(!root
        .path()
        .join(".kuzushi/v3/campaigns/one/queue.json")
        .exists());
}
