use super::*;
use kuzushi_core::{OptionScope, OptionTarget, V2Config};

fn options_view(tool_name: &str, filter: OptionsFilter) -> OptionsView {
    OptionsView {
        tool_name: tool_name.to_string(),
        filter,
    }
}

#[test]
fn option_display_names_humanize_canonical_keys() {
    assert_eq!(option_display_name("sampleLimit"), "Sample limit");
    assert_eq!(
        option_display_name("context_sample_limit"),
        "Context sample limit"
    );
    assert_eq!(option_display_name("budgetUsd"), "Budget USD");
    assert_eq!(
        option_display_name("THREAT_MODEL_PROMPT"),
        "Threat model prompt"
    );
}

#[test]
fn options_model_formats_stored_option_rows() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.option_store_mut().set_value(
        OptionScope::Session,
        OptionTarget::Tool("sast:scan".to_string()),
        "triage",
        serde_json::json!(true),
    );

    let model = options_model(&app, &options_view("sast:scan", OptionsFilter::Standard));
    let OptionsBody::Table(table) = &model.body else {
        panic!("expected ready options table");
    };
    let triage = table
        .rows
        .iter()
        .find(|row| row.cells[0] == "triage")
        .unwrap();

    assert_eq!(model.title, "OPTIONS");
    assert!(table.hint.contains("session-only"));
    assert!(table.hint.contains("lost on exit"));
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
    assert!(model.summary_rows.contains(&OptionsSummaryRow {
        cells: ["view".to_string(), "options".to_string()],
    }));
    assert_eq!(triage.cells[1], "true");
    assert_eq!(triage.cells[4], "bool");
    assert!(triage.has_stored_value);
}

#[test]
fn options_model_marks_unknown_tools() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = options_model(&app, &options_view("missing:tool", OptionsFilter::Standard));

    assert_eq!(
        model.body,
        OptionsBody::Message {
            message: "Unknown tool. Run tools to inspect the native registry.",
            plain_message: "Unknown tool. Next: tools",
        }
    );
    assert!(model.summary_rows.contains(&OptionsSummaryRow {
        cells: ["tool".to_string(), "missing:tool".to_string()],
    }));
}

#[test]
fn threat_model_options_surface_source_controls_as_standard_options() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = options_model(
        &app,
        &options_view("threat-model:build", OptionsFilter::Standard),
    );
    let OptionsBody::Table(table) = &model.body else {
        panic!("expected ready options table");
    };
    let names = table
        .rows
        .iter()
        .map(|row| row.cells[0].as_str())
        .collect::<Vec<_>>();

    for expected in ["methodology", "sources", "seed", "designDoc"] {
        assert!(names.contains(&expected), "missing {expected}: {names:?}");
    }
}

#[test]
fn threat_model_options_keep_low_level_source_controls_advanced() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = options_model(
        &app,
        &options_view("threat-model:build", OptionsFilter::Advanced),
    );
    let OptionsBody::Table(table) = &model.body else {
        panic!("expected ready advanced options table");
    };
    let names = table
        .rows
        .iter()
        .map(|row| row.cells[0].as_str())
        .collect::<Vec<_>>();

    for expected in ["contextMode", "contextLimit", "THREAT_MODEL_PROMPT"] {
        assert!(names.contains(&expected), "missing {expected}: {names:?}");
    }
}

#[test]
fn advanced_filter_lists_verify_escalation_model() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = options_model(
        &app,
        &options_view("verify:finding", OptionsFilter::Advanced),
    );
    let OptionsBody::Table(table) = &model.body else {
        panic!("expected ready advanced options table");
    };
    let names = table
        .rows
        .iter()
        .map(|row| row.cells[0].as_str())
        .collect::<Vec<_>>();

    assert!(
        names.contains(&"escalationModel"),
        "escalationModel missing from advanced verify options: {names:?}"
    );
}

#[test]
fn standard_filter_hides_escalation_model() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = options_model(
        &app,
        &options_view("verify:finding", OptionsFilter::Standard),
    );
    let OptionsBody::Table(table) = &model.body else {
        panic!("expected ready options table");
    };
    let names = table
        .rows
        .iter()
        .map(|row| row.cells[0].as_str())
        .collect::<Vec<_>>();

    assert!(
        !names.contains(&"escalationModel"),
        "escalationModel is advanced and must not appear in the standard view: {names:?}"
    );
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
    assert!(table.rows.iter().any(|row| row.cells[0] == "triage"));
    assert_eq!(
        table.note,
        "set is session-only (lost on exit); setg is persistent for this tool."
    );
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
