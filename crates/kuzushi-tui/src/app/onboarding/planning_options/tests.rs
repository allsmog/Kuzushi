use super::*;
use kuzushi_core::V2Config;
use serde_json::json;
use serde_json::Value;

#[test]
fn planning_overrides_are_scoped_to_the_task_preset() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let spec = app
        .registry()
        .resolve_tool("threat-model:build")
        .unwrap()
        .options
        .iter()
        .find(|spec| spec.name == "model")
        .unwrap()
        .clone();

    app.set_planning_option_override(
        PlanningTaskId::BuildStrideThreatModel,
        &spec,
        Value::String("openai:gpt-5.5".to_string()),
    )
    .unwrap();

    let stride = planning_task_explicit_input(
        PlanningTaskId::BuildStrideThreatModel,
        app.engagement.option_overrides(),
    );
    let pasta = planning_task_explicit_input(
        PlanningTaskId::BuildPastaThreatModel,
        app.engagement.option_overrides(),
    );
    assert_eq!(stride["methodology"], json!("stride"));
    assert_eq!(stride["model"], json!("openai:gpt-5.5"));
    assert_eq!(pasta["methodology"], json!("pasta"));
    assert!(pasta.get("model").is_none());
}

#[test]
fn context_task_becomes_model_backed_only_when_enrichment_is_selected() {
    let mut config = V2Config::default();
    config.model = Some("openai:gpt-5.5".to_string());
    let mut app = ShellApp::new(config, None);
    let task = PlanningTaskId::GatherRepoContext;

    assert!(!app.planning_task_model_backed(task));
    assert_eq!(app.planning_task_model(task), None);

    let enrichment = app.planning_option_spec(task, "enrichment").unwrap();
    app.set_planning_option_override(task, &enrichment, Value::Bool(true))
        .unwrap();

    assert!(app.planning_task_model_backed(task));
    assert_eq!(
        app.planning_task_model(task).as_deref(),
        Some("openai:gpt-5.5")
    );
}
