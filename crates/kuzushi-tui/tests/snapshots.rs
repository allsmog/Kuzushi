//! Snapshot tests pinning the design-driven plain-text rendering of each
//! key view at a fixed width (120 cols).
//!
//! Update with `cargo insta review` after intentional UI changes.

use kuzushi_core::{Finding, ScanCancellation, Severity, TriageOutcome, TriageVerdict, V2Config};
use kuzushi_tui::{render_plain_app, ShellApp, ShellCommand, ShellView, ThreatView};

const SNAPSHOT_WIDTH: usize = 120;

fn render_at_120(app: &ShellApp) -> String {
    render_plain_app(app, SNAPSHOT_WIDTH)
}

fn fresh_app() -> ShellApp {
    ShellApp::new(V2Config::default(), None)
}

fn _silence_unused() {
    // Bind unused imports so they show up in dependency graphs even when
    // a future test removes a usage.
    let _ = ScanCancellation::default;
    let _ = TriageVerdict::TruePositive;
}

#[test]
fn catalog_view_default() {
    let app = fresh_app();
    insta::with_settings!({
        prepend_module_to_snapshot => false,
        omit_expression => true,
    }, {
        insta::assert_snapshot!("catalog_view_default", render_at_120(&app));
    });
}

#[test]
fn threat_stories_view_with_canonical_fixture() {
    let mut app = fresh_app();
    app.shell_view = ShellView::Threat(ThreatView::Stories);
    insta::with_settings!({
        prepend_module_to_snapshot => false,
        omit_expression => true,
    }, {
        insta::assert_snapshot!("threat_stories_canonical", render_at_120(&app));
    });
}

#[test]
fn threat_scope_view_with_canonical_fixture() {
    let mut app = fresh_app();
    app.shell_view = ShellView::Threat(ThreatView::Scope);
    insta::with_settings!({
        prepend_module_to_snapshot => false,
        omit_expression => true,
    }, {
        insta::assert_snapshot!("threat_scope_canonical", render_at_120(&app));
    });
}

#[test]
fn threat_dfd_view_canonical_diagram() {
    let mut app = fresh_app();
    app.shell_view = ShellView::Threat(ThreatView::Dfd);
    insta::with_settings!({
        prepend_module_to_snapshot => false,
        omit_expression => true,
    }, {
        insta::assert_snapshot!("threat_dfd_canonical", render_at_120(&app));
    });
}

#[test]
fn threat_stride_view_with_canonical_fixture() {
    let mut app = fresh_app();
    app.shell_view = ShellView::Threat(ThreatView::Stride);
    insta::with_settings!({
        prepend_module_to_snapshot => false,
        omit_expression => true,
    }, {
        insta::assert_snapshot!("threat_stride_canonical", render_at_120(&app));
    });
}

#[test]
fn threat_summary_view_with_canonical_fixture() {
    let mut app = fresh_app();
    app.shell_view = ShellView::Threat(ThreatView::Summary);
    insta::with_settings!({
        prepend_module_to_snapshot => false,
        omit_expression => true,
    }, {
        insta::assert_snapshot!("threat_summary_canonical", render_at_120(&app));
    });
}

#[test]
fn module_view_focused_on_sast() {
    let mut app = fresh_app();
    app.handle_command(ShellCommand::Use("sast".to_string()));
    insta::with_settings!({
        prepend_module_to_snapshot => false,
        omit_expression => true,
    }, {
        insta::assert_snapshot!("module_view_sast", render_at_120(&app));
    });
}

#[test]
fn module_view_focused_on_recon_with_recent_activity() {
    let mut app = fresh_app();
    app.log.clear();
    app.log("recon:nmap", "discovered 5 hosts and 18 services for acme-checkout.com");
    app.log("recon:subdomain", "discovered 7 subdomains");
    app.log("recon", "persisted 3 findings");
    app.handle_command(ShellCommand::Use("recon".to_string()));
    insta::with_settings!({
        prepend_module_to_snapshot => false,
        omit_expression => true,
        filters => vec![
            // Strip elapsed timers / cost values that drift.
            (r"\$\d+\.\d{4}", "$0.0000"),
        ],
    }, {
        insta::assert_snapshot!("module_view_recon_active", render_at_120(&app));
    });
}

#[test]
fn module_run_view_with_findings_and_active_scan() {
    let mut app = fresh_app();
    let mut finding = Finding::new_semgrep(
        "demo.sql.injection",
        "apps/api/orders.rs",
        142,
        Some(142),
        Severity::Critical,
        "sql injection via order_id concatenation",
    );
    finding.triage = Some(TriageOutcome {
        verdict: TriageVerdict::TruePositive,
        confidence: 0.92,
        rationale: "input concatenated".to_string(),
    });
    app.findings.push(finding);
    app.scan = Some(kuzushi_tui::ScanPanelState {
        run_id: Some("run-abc1234".to_string()),
        target: std::path::PathBuf::from("./acme-checkout"),
        stage: "agentic-sast tracing".to_string(),
        findings_count: 1,
        running: true,
        abort_requested: false,
        error: None,
    });
    app.shell_view = ShellView::ModuleRun;
    insta::with_settings!({
        prepend_module_to_snapshot => false,
        omit_expression => true,
        filters => vec![
            (r"\$\d+\.\d{4}", "$0.0000"),
        ],
    }, {
        insta::assert_snapshot!("module_run_with_findings", render_at_120(&app));
    });
}
