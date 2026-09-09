use super::*;
use kuzushi_core::V2Config;

#[test]
fn config_model_summarizes_default_runtime_state() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = config_model(&app);

    assert_eq!(model.summary_title, "CONFIG");
    assert_eq!(model.model, "unconfigured");
    assert!(model.summary_rows.contains(&ConfigSummaryRow {
        cells: [
            "model".to_string(),
            "unconfigured · built-in default".to_string()
        ],
    }));
    assert!(model.summary_rows.contains(&ConfigSummaryRow {
        cells: [
            "reasoning".to_string(),
            "default · built-in default".to_string()
        ],
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
    let spark = crate::app::model_choices()
        .iter()
        .find(|choice| choice.id == "openai-codex:gpt-5.3-codex-spark")
        .expect("Codex Spark catalog row");
    assert_eq!(spark.provider, "openai-codex");
    assert!(spark.auth.starts_with("OAuth"));
    assert!(model
        .model_table
        .rows
        .iter()
        .any(|row| row.cells[2] == "openai-oauth:gpt-5.6-terra"));
    assert!(model
        .model_table
        .rows
        .iter()
        .any(|row| row.cells[2] == "openai-oauth:gpt-5.3-codex-spark"));
    assert!(model.model_table.rows.iter().all(|row| row.cells[0] != ">"));
    assert_eq!(
        model.commands,
        [
            "Up/Down scroll",
            "Enter model picker",
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
        cells: [
            "reasoning".to_string(),
            "xhigh · session selection".to_string()
        ],
    }));
}

#[test]
fn plain_config_model_projects_plain_summary_and_model_table() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = plain_config_model(&app);

    assert_eq!(model.summary_title, "CONFIG");
    assert!(model
        .summary_rows
        .contains(&"model: unconfigured · built-in default".to_string()));
    assert!(model
        .summary_rows
        .iter()
        .any(|row| row.starts_with("onboarding: model <n>")));
    assert_eq!(model.model_table.title, "MODELS");
    assert_eq!(model.model_table.headers, ["#", "model", "effort", "auth"]);
    assert!(!model.model_table.rows.is_empty());
    let spark = crate::app::model_choices()
        .iter()
        .find(|choice| choice.id == "openai-codex:gpt-5.3-codex-spark")
        .expect("Codex Spark catalog row");
    assert_eq!(spark.provider, "openai-codex");
    assert!(spark.auth.starts_with("OAuth"));
    assert!(model
        .model_table
        .rows
        .iter()
        .any(|row| row.cells[1] == "openai-oauth:gpt-5.6-terra"));
    assert!(model
        .model_table
        .rows
        .iter()
        .any(|row| row.cells[1] == "openai-oauth:gpt-5.3-codex-spark"));
    assert_eq!(
        model.next_hint,
        "Next: model <n> [xhigh], auth login openai, auth login anthropic, cost"
    );
}

#[test]
fn config_volunteers_operator_controls_and_unset_budget_truth() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = config_model(&app);
    let value = |label: &str| {
        model
            .summary_rows
            .iter()
            .find(|row| row.cells[0] == label)
            .map(|row| row.cells[1].as_str())
    };

    assert_eq!(
        value("session budget"),
        Some("not enforced · built-in default")
    );
    assert_eq!(
        value("hard ceiling"),
        Some("not configured · built-in default")
    );
    assert_eq!(
        value("stop after"),
        Some("not configured · built-in default")
    );
    assert_eq!(value("autonomy"), Some("fix · cap fix · built-in default"));
    assert!(value("operator config").is_some_and(|detail| detail.contains("config.toml")));
    assert!(value("operator options").is_some_and(|detail| detail.contains("options.json")));
    assert_eq!(
        value("notifications"),
        Some("on · focus unknown; desktop alerts unavailable")
    );
    assert_eq!(value("visualizations"), Some("auto-open on"));
}

#[test]
fn config_lists_every_stored_option_with_scope_and_redacts_sensitive_values() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.option_store_mut().set_value(
        kuzushi_core::OptionScope::Global,
        kuzushi_core::OptionTarget::Tool("semgrep:scan".to_string()),
        "paths",
        serde_json::json!(["src"]),
    );
    app.option_store_mut().set_value(
        kuzushi_core::OptionScope::Session,
        kuzushi_core::OptionTarget::Module("agentic-sast".to_string()),
        "api_token",
        serde_json::json!("do-not-render"),
    );

    let model = config_model(&app);
    let stored = model
        .summary_rows
        .iter()
        .filter(|row| row.cells[0].starts_with("stored option "))
        .map(|row| row.cells[1].as_str())
        .collect::<Vec<_>>();

    assert_eq!(stored.len(), 2);
    assert!(stored
        .iter()
        .any(|row| row.contains("operator options · tool semgrep:scan · paths=src")));
    assert!(stored.iter().any(|row| {
        row.contains("session option · module agentic-sast · api_token=[hidden]")
            && !row.contains("do-not-render")
    }));
}
