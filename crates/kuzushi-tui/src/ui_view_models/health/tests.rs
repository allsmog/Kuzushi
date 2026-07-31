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
                    credential_set: false,
                })
            }
            unexpected => panic!("unexpected health hydration key: {unexpected:?}"),
        }
    }
}

#[derive(Debug)]
struct FixedCpgArtifactsReader(bool);

impl ViewArtifactReader for FixedCpgArtifactsReader {
    fn read(&self, _target: &Path, key: &ViewHydrationKey) -> ViewHydrationValue {
        match key {
            ViewHydrationKey::CpgArtifacts => ViewHydrationValue::CpgArtifacts(self.0),
            unexpected => panic!("unexpected cpg-artifacts hydration key: {unexpected:?}"),
        }
    }
}

#[test]
fn cpg_graph_row_warns_when_no_graph_is_prebuilt() {
    let temp = tempfile::tempdir().unwrap();
    let row = cpg_graph_row(&app_targeting(temp.path()));

    assert_eq!(row.tone, HealthTone::Warn);
    assert!(row.detail.contains("grep-only"), "{row:?}");
    assert!(row.next.contains("cpg:build"), "{row:?}");
}

#[test]
fn cpg_graph_row_reads_the_cached_flag_not_the_render_path_disk() {
    // Disk truth: a usable current-shape whole graph exists. A render-path
    // `read_dir` would return Pass. But the cache says "no artifacts", so the
    // row must be Warn — proving `cpg_graph_row` reads only the cached value.
    let with_graph = tempfile::tempdir().unwrap();
    let dir = cpg_dir(with_graph.path());
    std::fs::write(
        dir.join(format!("go.v{}.cpg", kuzushi_core::CPG_GRAPH_SHAPE_VERSION)),
        b"x",
    )
    .unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(with_graph.path().to_path_buf()));
    app.set_view_artifact_reader_for_test(Arc::new(FixedCpgArtifactsReader(false)));
    app.hydrate_view_keys_blocking(with_graph.path(), vec![ViewHydrationKey::CpgArtifacts]);
    assert_eq!(cpg_graph_row(&app).tone, HealthTone::Warn);

    // Inverse: an empty dir on disk but the cache reports artifacts present —
    // the row is Pass, again reflecting the cache and not a synchronous read.
    let empty = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(empty.path().to_path_buf()));
    app.set_view_artifact_reader_for_test(Arc::new(FixedCpgArtifactsReader(true)));
    app.hydrate_view_keys_blocking(empty.path(), vec![ViewHydrationKey::CpgArtifacts]);
    assert_eq!(cpg_graph_row(&app).tone, HealthTone::Pass);
}

/// Targets the app and hydrates the cpg has_artifacts flag through the real
/// off-frame reader, so `cpg_graph_row` reads the cached truth (never a
/// render-path `read_dir`) yet still reflects real on-disk artifact shape.
fn app_targeting(target: &Path) -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(target.to_path_buf()));
    app.hydrate_view_keys_blocking(target, vec![ViewHydrationKey::CpgArtifacts]);
    app
}

fn cpg_dir(target: &Path) -> std::path::PathBuf {
    let dir = target.join(".kuzushi").join("cpg-rs");
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn cpg_graph_row_warns_when_only_scoped_or_stale_graphs_exist() {
    let temp = tempfile::tempdir().unwrap();
    let dir = cpg_dir(temp.path());
    // A stale-shape graph and a scoped graph — neither is a usable whole-graph
    // artifact for the current shape version.
    std::fs::write(dir.join("go.v1.cpg"), b"x").unwrap();
    let scoped = dir.join("scoped").join("svc");
    std::fs::create_dir_all(&scoped).unwrap();
    std::fs::write(
        scoped.join(format!("go.v{}.cpg", kuzushi_core::CPG_GRAPH_SHAPE_VERSION)),
        b"x",
    )
    .unwrap();

    let row = cpg_graph_row(&app_targeting(temp.path()));

    assert_eq!(row.tone, HealthTone::Warn, "{row:?}");
    assert!(row.detail.contains("grep-only"), "{row:?}");
}

#[test]
fn cpg_graph_row_passes_only_with_a_current_shape_whole_graph() {
    let temp = tempfile::tempdir().unwrap();
    let dir = cpg_dir(temp.path());
    std::fs::write(
        dir.join(format!("go.v{}.cpg", kuzushi_core::CPG_GRAPH_SHAPE_VERSION)),
        b"x",
    )
    .unwrap();

    let row = cpg_graph_row(&app_targeting(temp.path()));

    assert_eq!(row.tone, HealthTone::Pass, "{row:?}");
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
    assert_eq!(model.summary, "health: 1 failing, 4 warning");
    assert_eq!(model.footer.stage, model.summary);
    assert!(!model
        .body_rows
        .iter()
        .any(|row| row.contains("0 failing, 7 warning")));
}
