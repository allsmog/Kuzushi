use super::*;
use kuzushi_core::V2Config;

#[test]
fn auth_provider_rows_hide_secret_values() {
    let app = ShellApp::new(V2Config::default(), None);

    let rows = auth_provider_rows(&app);

    assert_eq!(rows.len(), 3);
    assert!(rows.iter().any(|row| row.name == "pi-agent-core"));
    assert!(!rows.iter().any(|row| row.detail.contains("sk-")));
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
