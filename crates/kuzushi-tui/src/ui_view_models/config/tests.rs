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
        cells: ["reasoning".to_string(), "default".to_string()],
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
    assert!(model.model_table.rows.iter().all(|row| row.cells[0] != ">"));
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
fn config_marks_only_the_exact_canonical_catalog_model() {
    let mut config = V2Config::default();
    config.model = Some(" openai:gpt-5.5 ".to_string());
    let app = ShellApp::new(config, None);

    let model = config_model(&app);
    let selected = model
        .model_table
        .rows
        .iter()
        .filter(|row| row.cells[0] == ">")
        .collect::<Vec<_>>();

    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].cells[2], "openai:gpt-5.5");
}

#[test]
fn config_prepends_truthful_explicit_row_for_model_outside_catalog() {
    let mut config = V2Config::default();
    config.model = Some("openai-codex:gpt-5.5".to_string());
    let app = ShellApp::new(config, None);

    let model = config_model(&app);
    let explicit = &model.model_table.rows[0];

    assert_eq!(explicit.cells[0], ">");
    assert_eq!(explicit.cells[1], "explicit");
    assert_eq!(explicit.cells[2], "openai-oauth:gpt-5.5");
    assert!(model
        .model_table
        .rows
        .iter()
        .skip(1)
        .all(|row| row.cells[0] != ">"));
}

#[test]
fn config_model_reports_session_cost_when_available() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.session_mut().set_session_cost_usd_for_test(0.0456);
    app.session_mut()
        .set_last_tool_cost_usd_for_test(Some(0.0123));

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
    app.set_session_thinking_level(Some("xhigh".to_string()));

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
