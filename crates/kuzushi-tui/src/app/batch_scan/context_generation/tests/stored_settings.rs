use super::*;
use kuzushi_core::options::{OptionScope, OptionTarget};

#[test]
fn stored_settings_prepare_the_same_bounded_setup_plan_without_global_role_keys() {
    let (root, mut app) = fixture();
    app.option_store_mut().set_value(
        OptionScope::Global,
        OptionTarget::All,
        "MODEL_TRIAGE_ESCALATION",
        json!("openai-codex:gpt-5.5"),
    );
    app.option_store_mut().set_value(
        OptionScope::Global,
        OptionTarget::Tool("threat-model:build".into()),
        "maxSourceBytes",
        json!("4096"),
    );
    app.router.campaign_mut().batch_scan_config = None;
    app.open_setup();
    app.set_input("Held Setup draft");
    app.set_cursor(4);
    let plan = [
        crate::app::PlanningTaskId::GatherRepoContext,
        crate::app::PlanningTaskId::MapEntryPoints,
        crate::app::PlanningTaskId::BuildThreatModel,
    ];
    app.review_model_backed_map(&plan).unwrap();
    assert_eq!(
        app.context_generation().unwrap().context_input,
        json!({"maxSourceBytes":4096})
    );
    let result = prepare(&mut app, root.path());
    app.cache_tool_snapshot("campaign:context-study", &result);
    assert!(app.context_generation().unwrap().receipt.is_some());
    assert!(app.router.campaign().dispatcher_pid.is_none());
    assert_eq!(app.input(), "Held Setup draft");
    assert_eq!(app.cursor(), 4);
}
