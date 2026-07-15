use super::*;
use crate::app::{
    ShellView, ViewArtifactReader, ViewHealthChecks, ViewHydrationKey, ViewHydrationValue,
};
use kuzushi_core::V2Config;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug)]
struct SettledHealthReader;

impl ViewArtifactReader for SettledHealthReader {
    fn read(&self, _target: &Path, key: &ViewHydrationKey) -> ViewHydrationValue {
        match key {
            ViewHydrationKey::HealthChecks { .. } => {
                ViewHydrationValue::HealthChecks(ViewHealthChecks {
                    semgrep_error: Some("semgrep unavailable".to_string()),
                    codeql_error: None,
                    joern_path: None,
                    credential_set: false,
                    configured_joern_cpg: None,
                })
            }
            unexpected => panic!("unexpected health hydration key: {unexpected:?}"),
        }
    }
}

#[test]
fn cold_health_summary_reports_loading_instead_of_partial_totals() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = health_model(&app);

    assert_eq!(model.summary, "health checks loading");
    assert!(model.rows.iter().any(|row| row.tone == HealthTone::Pending));
}

#[test]
fn settled_health_model_shares_failing_warning_totals_and_missing_context() {
    let mut config = V2Config::default();
    config.model = None;
    let mut app = ShellApp::new(config, None);
    app.set_view_artifact_reader_for_test(Arc::new(SettledHealthReader));
    app.set_shell_view(ShellView::Health);
    app.hydrate_active_view_blocking();

    let model = health_display_model(&app);

    assert_eq!(model.status.ctx, "not built");
    assert_eq!(model.summary, "health: 2 failing, 4 warning");
    assert_eq!(model.footer.stage, model.summary);
    assert!(!model
        .body_rows
        .iter()
        .any(|row| row.contains("0 failing, 7 warning")));
}
