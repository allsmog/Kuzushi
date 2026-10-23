use super::*;
use crate::app::EffectRuntime;
use std::path::Path;

fn refused_workspace() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    assert!(std::process::Command::new("git")
        .args(["init", "--initial-branch=main", "-q"])
        .arg(root.path())
        .status()
        .unwrap()
        .success());
    std::fs::write(root.path().join("source.rs"), "// Owned inert source.\n").unwrap();
    std::fs::write(root.path().join(".gitignore"), ".kuzushi/\n").unwrap();
    root
}

#[test]
fn workspace_refusal_clears_scope_pending_and_shows_the_actual_reason() {
    let root = refused_workspace();
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_target(Some(root.path().into()));
    app.set_input("unsent operator draft");
    app.set_cursor(7);
    let effects = app.open_scope_review();
    assert!(app.scope_review().unwrap().pending.is_some());
    EffectRuntime::execute(&mut app, effects);
    let state = app.scope_review().unwrap();
    assert!(
        state.pending.is_none(),
        "workspace refusal left a phantom request"
    );
    assert!(state.notice.as_ref().unwrap().contains("scope.toml"));
    assert!(state.review.is_none());
    assert!(!app.has_running_work());
    assert_eq!((app.input(), app.cursor()), ("unsent operator draft", 7));
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
}

fn pending_scope(root: &Path) -> ShellApp {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_target(Some(root.into()));
    let effects = app.open_scope_review();
    assert!(matches!(
        effects.as_slice(),
        [ShellEffect::PrepareRunTool(_)]
    ));
    app
}

fn prepare_scope(app: &mut ShellApp, target: &Path, input: &str) -> Vec<ShellEffect> {
    app.prepare_run_tool_launch(RunToolPreparation {
        tool_name: "pack:scopes".into(),
        input: Some(input.into()),
        target: Some(target.into()),
    })
}

#[test]
fn malformed_or_unknown_scope_options_end_the_pending_request() {
    for (input, expected) in [
        ("{", "invalid"),
        (
            r#"{"operation":"latest","unknownExample":true}"#,
            "unknownExample",
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut app = pending_scope(root.path());
        assert!(prepare_scope(&mut app, root.path(), input).is_empty());
        let state = app.scope_review().unwrap();
        assert!(state.pending.is_none());
        assert!(state.notice.as_ref().unwrap().contains(expected));
        assert!(!app.has_running_work());
    }
}

#[test]
fn refusal_for_an_earlier_target_does_not_clear_the_new_targets_request() {
    let refused = refused_workspace();
    let current = tempfile::tempdir().unwrap();
    let mut app = pending_scope(current.path());
    let pending = app.scope_review().unwrap().pending.clone();
    let notice = app.scope_review().unwrap().notice.clone();
    assert!(prepare_scope(&mut app, refused.path(), r#"{"operation":"latest"}"#).is_empty());
    assert_eq!(app.scope_review().unwrap().pending, pending);
    assert_eq!(app.scope_review().unwrap().notice, notice);
    assert_eq!(app.target(), Some(current.path()));
    assert!(!app.has_running_work());
}

#[test]
fn corrected_workspace_can_prepare_an_explicit_retry() {
    let root = refused_workspace();
    let mut app = pending_scope(root.path());
    assert!(prepare_scope(&mut app, root.path(), r#"{"operation":"latest"}"#).is_empty());
    assert!(app.scope_review().unwrap().pending.is_none());
    std::fs::write(
        root.path().join(".gitignore"),
        "# Workspace state manages its own ignore policy.\n",
    )
    .unwrap();
    let effects = app
        .dispatch_scope_request(serde_json::json!({"operation":"latest"}))
        .effects;
    let Some(ShellEffect::PrepareRunTool(prepare)) = effects.into_iter().next() else {
        panic!("explicit retry must prepare one request")
    };
    let launch = app.prepare_run_tool_launch(prepare);
    assert!(matches!(
        launch.as_slice(),
        [ShellEffect::DispatchRunTool(_)]
    ));
    assert!(app.scope_review().unwrap().pending.is_some());
    assert!(!app.has_running_work());
}

#[test]
fn workspace_refusal_is_visible_in_the_context_plan_without_losing_inputs() {
    let root = refused_workspace();
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_target(Some(root.path().into()));
    let input = serde_json::json!({"maxSourceBytes":8192,"THREAT_MODEL_PROMPT":"Keep the operator's context guidance"});
    let mut config = crate::app::BatchScanConfig::load_for_map_study(root.path());
    config.context_generation = Some(crate::app::StudyContextGeneration {
        context_input: input.clone(),
        ..Default::default()
    });
    app.router.campaign_mut().batch_scan_config = Some(config);
    let effects=app.prepare_run_tool_launch(RunToolPreparation {tool_name:"campaign:context-study".into(),
        input:Some(serde_json::json!({"campaignId":"kept-draft","investigationId":"fixture-only","contextInput":input}).to_string()),
        target:app.target_owned()});
    assert!(effects.is_empty());
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert!(config.notice.as_ref().unwrap().contains("scope.toml"));
    let generation = config.context_generation.as_ref().unwrap();
    assert_eq!(generation.context_input, input);
    assert!(generation.receipt.is_none());
    assert!(config.study.allowance.is_none());
    assert!(!app.has_running_work());
}
