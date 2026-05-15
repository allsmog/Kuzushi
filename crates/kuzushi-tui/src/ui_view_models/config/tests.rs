use super::*;
use kuzushi_core::V2Config;

#[test]
fn config_model_summarizes_default_runtime_state() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = config_model(&app);

    assert_eq!(model.model, "unconfigured");
    assert_eq!(model.reasoning, "default");
    assert!(model.onboarding.is_some());
    assert!(!model.model_rows.is_empty());
    assert!(model.model_rows[app.selected_model_index].selected);
}

#[test]
fn config_model_reports_session_cost_when_available() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.session_cost_usd = 0.0456;
    app.last_tool_cost_usd = Some(0.0123);

    let model = config_model(&app);

    assert_eq!(model.cost, "session $0.0456; last tool $0.0123");
}

#[test]
fn config_model_preserves_explicit_reasoning_override() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.session_thinking_level = Some("xhigh".to_string());

    let model = config_model(&app);

    assert_eq!(model.reasoning, "xhigh");
    assert_eq!(model.reasoning_override, Some("xhigh".to_string()));
}
