use super::*;
use kuzushi_core::V2Config;

#[test]
fn config_model_summarizes_default_runtime_state() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = config_model(&app);

    assert_eq!(model.summary_title, "CONFIG");
    assert_eq!(model.model, "unconfigured");
    assert!(model.summary_rows.contains(&ConfigSummaryRow {
        cells: ["model".to_string(), "unconfigured".to_string()],
    }));
    assert!(model.summary_rows.contains(&ConfigSummaryRow {
        cells: ["reasoning".to_string(), "xhigh".to_string()],
    }));
    assert!(model
        .summary_rows
        .iter()
        .any(|row| row.cells[0] == "onboarding"));
    // Build provenance row: published vs working-tree builds must be
    // distinguishable. Value is compile-time (sha · profile) — assert the
    // version prefix only.
    assert!(model
        .summary_rows
        .iter()
        .any(|row| row.cells[0] == "build" && row.cells[1].starts_with(env!("CARGO_PKG_VERSION"))));
    assert_eq!(model.model_table.title, "MODELS");
    assert_eq!(
        model.model_table.headers,
        ["", "#", "model", "effort", "auth"]
    );
    assert!(!model.model_table.rows.is_empty());
    assert!(!model
        .model_table
        .rows
        .iter()
        .flat_map(|row| row.cells.iter())
        .any(|cell| cell.contains("openai-codex") || cell.contains("codex")));
    assert!(model.model_table.rows.iter().any(|row| row.cells[0] == ">"));
    assert_eq!(
        model.commands,
        [
            "Up/Down select",
            "Enter choose",
            "model <n> [xhigh]",
            "auth login openai|anthropic",
        ]
    );
}

#[test]
fn config_model_reports_session_cost_when_available() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.session_cost_usd = 0.0456;
    app.last_tool_cost_usd = Some(0.0123);

    let model = config_model(&app);

    assert!(model.summary_rows.contains(&ConfigSummaryRow {
        cells: [
            "cost".to_string(),
            "session $0.0456; last tool $0.0123".to_string(),
        ],
    }));
}

#[test]
fn config_model_preserves_explicit_reasoning_override() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.session_thinking_level = Some("xhigh".to_string());

    let model = config_model(&app);

    assert_eq!(model.reasoning_override, Some("xhigh".to_string()));
    assert!(model.summary_rows.contains(&ConfigSummaryRow {
        cells: ["reasoning".to_string(), "xhigh".to_string()],
    }));
}

#[test]
fn plain_config_model_projects_plain_summary_and_model_table() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = plain_config_model(&app);

    assert_eq!(model.summary_title, "CONFIG");
    assert!(model
        .summary_rows
        .contains(&"model: unconfigured".to_string()));
    assert!(model
        .summary_rows
        .iter()
        .any(|row| row.starts_with("onboarding: model <n>")));
    assert_eq!(model.model_table.title, "MODELS");
    assert_eq!(model.model_table.headers, ["#", "model", "effort", "auth"]);
    assert!(!model.model_table.rows.is_empty());
    assert!(!model
        .model_table
        .rows
        .iter()
        .flat_map(|row| row.cells.iter())
        .any(|cell| cell.contains("openai-codex") || cell.contains("codex")));
    assert_eq!(
        model.next_hint,
        "Next: model <n> [xhigh], auth login openai, auth login anthropic, cost"
    );
}
