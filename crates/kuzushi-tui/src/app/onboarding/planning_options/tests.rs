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
fn ordinary_map_options_hide_advanced_enrichment() {
    let app = ShellApp::new(V2Config::default(), None);

    let option_names = app
        .standard_planning_options(PlanningTaskId::GatherRepoContext.tool_name())
        .into_iter()
        .map(|spec| spec.name)
        .collect::<Vec<_>>();

    assert_eq!(option_names, vec!["sampleLimit", "discovery", "scope"]);
    let enrichment = app
        .planning_option_spec(PlanningTaskId::GatherRepoContext, "enrichment")
        .expect("context enrichment descriptor");
    assert!(enrichment.advanced);
    assert_eq!(enrichment.default, Some(json!(false)));
}
