use super::*;
use crate::modules::ModuleRegistry;
use crate::run_artifacts::{list_run_summary_entries, write_run_summary, TraceHandle};
use crate::{RunSummary, RunSummaryEntryState, V2Config, WorkspaceTarget};

fn context<'a>(
    config: &'a V2Config,
    workspace: &'a WorkspaceTarget,
    trace: Option<&'a TraceHandle>,
) -> ToolExecutionContext<'a> {
    ToolExecutionContext {
        config,
        workspace: Some(workspace),
        findings_store: None,
        trace,
        cancellation: None,
        authorization: Default::default(),
    }
}

#[test]
fn both_input_parsers_attach_default_outputs_to_the_producing_run() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config {
        model: Some("openai-codex:gpt-5.5".into()),
        ..Default::default()
    };
    let trace = TraceHandle::jsonl(root.path(), "owned-context-run");
    let ctx = context(&config, &workspace, Some(&trace));
    for flavor in [BuildFlavor::ThreatModel, BuildFlavor::RandoriPasta] {
        let expected = flavor.default_output_dir(root.path(), "owned-context-run");
        assert_eq!(
            parse_build_input(&json!({}), &ctx, flavor)
                .unwrap()
                .output_dir,
            expected
        );
        assert_eq!(
            parse_deterministic_build_input(&json!({}), &ctx, flavor)
                .unwrap()
                .output_dir,
            expected
        );
    }
}

#[test]
fn explicit_output_paths_and_their_alias_keep_priority() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let trace = TraceHandle::jsonl(root.path(), "owned-context-run");
    let ctx = context(&config, &workspace, Some(&trace));
    for key in ["outputDir", "output_dir"] {
        let input = json!({key: ".kuzushi/owned-context-output"});
        assert_eq!(
            resolve_build_output_dir(&input, &ctx, BuildFlavor::ThreatModel, root.path()),
            ".kuzushi/owned-context-output"
        );
    }
}

#[test]
fn untraced_callers_keep_distinct_historical_output_directories() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let ctx = context(&config, &workspace, None);
    let first = resolve_build_output_dir(&json!({}), &ctx, BuildFlavor::ThreatModel, root.path());
    let second = resolve_build_output_dir(&json!({}), &ctx, BuildFlavor::ThreatModel, root.path());
    assert_ne!(first, second);
    let run = Path::new(&first)
        .parent()
        .unwrap()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap();
    Uuid::parse_str(run).unwrap();
    assert_eq!(
        first,
        BuildFlavor::ThreatModel.default_output_dir(root.path(), run)
    );
}

#[test]
fn prepared_context_build_creates_no_metadata_less_run() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("main.rs"),
        "// Owned source-only greeting fixture.\nfn main() {}\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let trace = TraceHandle::jsonl(root.path(), "owned-context-run");
    let ctx = context(&config, &workspace, Some(&trace));
    let summary = RunSummary::running(
        "owned-context-run",
        "threat-model:build",
        None,
        root.path().to_string_lossy(),
    );
    write_run_summary(root.path(), &summary).unwrap();
    let registry = ModuleRegistry::with_v2_builtins();
    let input = json!({"pipeline":"deterministic", "activate":false, "preserveUserEdits":false});
    let prepared = registry
        .prepare_dispatch_input("threat-model:build", input, &ctx, None)
        .unwrap();
    let result = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    let expected = BuildFlavor::ThreatModel.default_output_dir(root.path(), "owned-context-run");
    let artifact = root
        .path()
        .join(expected)
        .join("normalized-threat-model.json")
        .canonicalize()
        .unwrap();
    assert_eq!(
        result["data"]["normalizedArtifact"],
        artifact.to_string_lossy().as_ref()
    );
    assert!(artifact.is_file());
    let entries = list_run_summary_entries(root.path()).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].run_id, "owned-context-run");
    assert!(matches!(entries[0].state, RunSummaryEntryState::Ready(_)));
}
