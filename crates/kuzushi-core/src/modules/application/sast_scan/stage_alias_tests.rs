use super::*;
use crate::modules::input::SastTaskSelectionSource;

#[test]
fn standalone_stages_cannot_expand_into_the_legacy_systems_engine() {
    for task in [
        "systems-hunt:systems-context-gatherer",
        "systems-hunt:systems-invariant-extract",
        "systems-hunt:systems-trigger-synth",
        "deep-semantic",
        "deep-semantic-hunt",
        "systems-hunt:deep-semantic-hunt",
    ] {
        let result =
            SastTaskSelection::from_tasks(vec![task.into()], SastTaskSelectionSource::Explicit);
        assert!(
            result.is_err(),
            "standalone stage {task} must not select a larger workflow"
        );
        assert!(result.err().unwrap().to_string().contains("standalone"));
        assert!(!crate::modules::runtime_requirements::wants_sast_runtime(
            &json!({"tasks":[task]})
        ));
    }
}

#[test]
fn exact_legacy_bundle_requests_keep_their_explicit_identity_without_execution() {
    for task in ["systems", "systems-hunt", "systems-hunt:systems-hunt"] {
        let selected =
            SastTaskSelection::from_tasks(vec![task.into()], SastTaskSelectionSource::Explicit)
                .unwrap();
        assert!(selected.run_systems_hunt);
        assert!(!selected.run_agentic && !selected.run_carlini && !selected.run_taint_iris_next);
    }
}

#[test]
fn shared_preparation_refuses_stage_expansion_before_model_or_finding_store_requirements() {
    let root = tempfile::tempdir().unwrap();
    let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
    let config = crate::V2Config::default();
    let ctx = crate::ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = crate::ModuleRegistry::with_v2_builtins();
    for tasks in [
        json!(["systems-hunt:systems-context-gatherer"]),
        json!(["secret-scan", "systems-hunt:deep-semantic-hunt"]),
    ] {
        let error = registry
            .prepare_dispatch_input(
                "sast:scan",
                json!({"tasks":tasks,"taskMode":"manual"}),
                &ctx,
                None,
            )
            .unwrap_err();
        assert!(format!("{error:#}").contains("standalone stage"));
    }
    assert!(!workspace.findings_db_path().exists());
}
