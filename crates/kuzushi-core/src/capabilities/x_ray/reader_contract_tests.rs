use super::*;
use crate::modules::{ModuleRegistry, ToolExecutionContext};
use serde_json::json;

fn fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("x-ray");
    std::fs::create_dir(&dir).unwrap();
    for (name, text) in [
        ("x-ray.md", "## X-Ray Verdict\nREADY\nOwned report claim.\n"),
        ("entry-points.md", "# Entry Points\n"),
        ("invariants.md", "# Invariants\n"),
        (
            "architecture.svg",
            "<svg xmlns=\"http://www.w3.org/2000/svg\"/>\n",
        ),
    ] {
        std::fs::write(dir.join(name), text).unwrap();
    }
    root
}

#[test]
fn reader_is_auxiliary_and_generation_spend_is_unknown() {
    let root = fixture();
    let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
    let config = crate::V2Config::default();
    let context = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let result = registry
        .execute_tool("x-ray:read", json!({}), &context)
        .unwrap();
    assert!(!registry.resolve_tool("x-ray:read").unwrap().phase_result);
    assert_eq!(result["data"]["costUsdExact"], false);
    assert_eq!(
        result["data"]["readProvenance"]["sourceFreshness"],
        "not-assessed"
    );
    assert_eq!(
        result["data"]["readProvenance"]["generationSpend"],
        "unknown"
    );
    assert_eq!(result["data"]["verdict"]["tier"], "READY");
    assert!(result["summary"]
        .as_str()
        .unwrap()
        .contains("Recorded report tier"));
}

#[test]
fn reader_refuses_oversized_architecture_artifact() {
    let root = fixture();
    let path = root.path().join("x-ray/architecture.svg");
    let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.set_len(8 * 1024 * 1024 + 1).unwrap();
    assert!(read_x_ray_report_artifacts(root.path(), None, "rust", 0.0).is_err());
    assert_eq!(path.metadata().unwrap().len(), 8 * 1024 * 1024 + 1);
}

#[test]
fn reader_requires_an_explicit_target_or_workspace() {
    let config = crate::V2Config::default();
    let context = ToolExecutionContext {
        config: &config,
        workspace: None,
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let error = execute_x_ray_tool("x-ray:read", json!({}), &context, None).unwrap_err();
    assert!(error
        .to_string()
        .contains("explicit target or active workspace"));
}

#[test]
fn reader_target_is_declared_and_unknown_keys_refuse_preparation() {
    let root = fixture();
    let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
    let config = crate::V2Config::default();
    let context = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let input = json!({"target":workspace.root().display().to_string()});
    let result = registry
        .execute_tool("x-ray:read", input, &context)
        .unwrap();
    assert_eq!(
        result["data"]["target"],
        workspace.root().display().to_string()
    );
    assert!(registry
        .prepare_dispatch_input("x-ray:read", json!({"unknown":true}), &context, None)
        .is_err());
}

#[test]
fn reader_rejects_invalid_markdown_without_rewriting_artifacts() {
    let root = fixture();
    let path = root.path().join("x-ray/entry-points.md");
    std::fs::write(&path, [0xff, 0xfe]).unwrap();
    assert!(read_x_ray_report_artifacts(root.path(), None, "rust", 0.0).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), [0xff, 0xfe]);
}

#[test]
fn cancelled_reader_does_not_load_missing_artifacts() {
    let root = tempfile::tempdir().unwrap();
    let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
    let config = crate::V2Config::default();
    let cancellation = crate::scan::ScanCancellation::default();
    cancellation.cancel();
    let context = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: Some(&cancellation),
        authorization: Default::default(),
    };
    let error = execute_x_ray_tool("x-ray:read", json!({}), &context, None).unwrap_err();
    assert!(error.to_string().contains("cancelled"));
    assert!(!workspace.root().join("x-ray").exists());
}
