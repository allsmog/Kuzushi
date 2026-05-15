use super::*;
use kuzushi_core::{OptionScope, OptionTarget, V2Config};

fn options_view(tool_name: &str, filter: OptionsFilter) -> OptionsView {
    OptionsView {
        tool_name: tool_name.to_string(),
        filter,
    }
}

#[test]
fn options_model_formats_stored_option_rows() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.option_store.set_value(
        OptionScope::Session,
        OptionTarget::Tool("sast:scan".to_string()),
        "triage",
        serde_json::json!(true),
    );

    let model = options_model(&app, &options_view("sast:scan", OptionsFilter::Standard));
    let triage = model.rows.iter().find(|row| row.name == "triage").unwrap();

    assert_eq!(model.status, OptionsModelStatus::Ready);
    assert_eq!(model.filter_label, "options");
    assert_eq!(triage.value, "true");
    assert_eq!(triage.option_type, "bool");
    assert!(triage.has_stored_value);
}

#[test]
fn options_model_marks_unknown_tools() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = options_model(&app, &options_view("missing:tool", OptionsFilter::Standard));

    assert_eq!(model.status, OptionsModelStatus::UnknownTool);
    assert!(model.rows.is_empty());
}
