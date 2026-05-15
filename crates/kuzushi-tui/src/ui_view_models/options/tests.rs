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

    assert_eq!(model.title, "OPTIONS");
    assert_eq!(model.status, OptionsModelStatus::Ready);
    assert!(model.summary_rows.contains(&OptionsSummaryRow {
        label: "view",
        value: "options".to_string(),
    }));
    assert_eq!(triage.value, "true");
    assert_eq!(triage.option_type, "bool");
    assert!(triage.has_stored_value);
}

#[test]
fn options_model_marks_unknown_tools() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = options_model(&app, &options_view("missing:tool", OptionsFilter::Standard));

    assert_eq!(model.status, OptionsModelStatus::UnknownTool);
    assert!(model.summary_rows.contains(&OptionsSummaryRow {
        label: "tool",
        value: "missing:tool".to_string(),
    }));
    assert!(model.rows.is_empty());
}

#[test]
fn plain_options_model_projects_ready_table() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = plain_options_model(&app, &options_view("sast:scan", OptionsFilter::Standard));

    assert_eq!(model.title, "OPTIONS");
    assert_eq!(
        model.summary_rows,
        vec!["tool: sast:scan".to_string(), "view: options".to_string()]
    );
    let PlainOptionsBody::Table(table) = model.body else {
        panic!("expected ready options table");
    };
    assert_eq!(
        table.headers,
        [
            "option",
            "value",
            "default",
            "req",
            "type",
            "aliases",
            "description"
        ]
    );
    assert!(table.rows.iter().any(|row| row.name == "triage"));
    assert_eq!(
        table.next_hint,
        "Next: set <key> <value>, setg <key> <value>, show advanced, show missing"
    );
}

#[test]
fn plain_options_model_projects_unknown_tool_message() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = plain_options_model(&app, &options_view("missing:tool", OptionsFilter::Standard));

    assert_eq!(
        model.body,
        PlainOptionsBody::Message(vec!["Unknown tool. Next: tools".to_string()])
    );
}
