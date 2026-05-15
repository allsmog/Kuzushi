use super::*;
use kuzushi_core::V2Config;

#[test]
fn auth_provider_rows_hide_secret_values() {
    let app = ShellApp::new(V2Config::default(), None);

    let rows = auth_provider_rows(&app);

    assert_eq!(rows.len(), 3);
    assert!(rows.iter().any(|row| row.cells[0] == "pi-agent-core"));
    assert!(!rows.iter().any(|row| row.cells[2].contains("sk-")));
}

#[test]
fn auth_env_summary_names_keys_without_secret_values() {
    let app = ShellApp::new(V2Config::default(), None);

    let summary = auth_env_summary(&app);

    assert!(summary.contains(&app.config.runtime.api_key_env));
    assert!(summary.contains("ANTHROPIC_API_KEY"));
    assert!(!summary.contains("sk-"));
}

#[test]
fn oauth_summary_reports_both_provider_slots() {
    let summary = oauth_summary();

    assert!(summary.contains("openai"));
    assert!(summary.contains("anthropic"));
}

#[test]
fn model_auth_status_reports_choice_auth_for_unknown_provider() {
    let choice = crate::app::ModelChoice {
        index: 99,
        provider: "local",
        id: "local:demo",
        label: "local demo",
        thinking_level: "default",
        auth: "manual",
    };

    assert_eq!(model_auth_status(&choice), "manual");
}
