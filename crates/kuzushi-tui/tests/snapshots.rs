//! Snapshot tests pinning the design-driven plain-text rendering of each
//! key view at a fixed width (120 cols).
//!
//! Snapshot fixtures are checked directly to keep tests offline-friendly.

use std::{fs, path::PathBuf};

use kuzushi_core::{Finding, ScanCancellation, Severity, TriageOutcome, TriageVerdict, V2Config};
use kuzushi_tui::{
    render_plain_app, OptionsFilter, OptionsView, ShellApp, ShellCommand, ShellView, ThreatView,
};

const SNAPSHOT_WIDTH: usize = 120;

fn render_at_120(app: &ShellApp) -> String {
    render_plain_app(app, SNAPSHOT_WIDTH)
}

fn fresh_app() -> ShellApp {
    ShellApp::new(V2Config::default(), None)
}

fn assert_plain_snapshot(name: &str, actual: &str) {
    let path = snapshot_path(name);
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    let (header, expected) = split_snapshot(&raw);
    if std::env::var_os("KUZUSHI_UPDATE_SNAPSHOTS").is_some() {
        fs::write(&path, format!("{}{}\n", header, actual.trim_end()))
            .unwrap_or_else(|error| panic!("failed to write {}: {error}", path.display()));
        return;
    }
    assert_eq!(
        expected.trim_end(),
        actual.trim_end(),
        "snapshot {name} differed"
    );
}

fn split_snapshot(raw: &str) -> (String, &str) {
    let Some((_, rest)) = raw.split_once("---\n") else {
        return (String::new(), raw);
    };
    let Some((metadata, body)) = rest.split_once("---\n") else {
        return (String::new(), raw);
    };
    (format!("---\n{}---\n", metadata), body)
}

fn snapshot_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("snapshots")
        .join(format!("{name}.snap"))
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
    assert_plain_snapshot("catalog_view_default", &render_at_120(&app));
}

#[test]
fn threat_stories_view_with_canonical_fixture() {
    let mut app = fresh_app();
    app.shell_view = ShellView::Threat(ThreatView::Stories);
    assert_plain_snapshot("threat_stories_canonical", &render_at_120(&app));
}

#[test]
fn threat_scope_view_with_canonical_fixture() {
    let mut app = fresh_app();
    app.shell_view = ShellView::Threat(ThreatView::Scope);
    assert_plain_snapshot("threat_scope_canonical", &render_at_120(&app));
}

#[test]
fn threat_dfd_view_canonical_diagram() {
    let mut app = fresh_app();
    app.shell_view = ShellView::Threat(ThreatView::Dfd);
    assert_plain_snapshot("threat_dfd_canonical", &render_at_120(&app));
}

#[test]
fn threat_stride_view_with_canonical_fixture() {
    let mut app = fresh_app();
    app.shell_view = ShellView::Threat(ThreatView::Stride);
    assert_plain_snapshot("threat_stride_canonical", &render_at_120(&app));
}

#[test]
fn threat_summary_view_with_canonical_fixture() {
    let mut app = fresh_app();
    app.shell_view = ShellView::Threat(ThreatView::Summary);
    assert_plain_snapshot("threat_summary_canonical", &render_at_120(&app));
}

#[test]
fn module_view_focused_on_sast() {
    let mut app = fresh_app();
    app.handle_command(ShellCommand::Use("sast".to_string()));
    assert_plain_snapshot("module_view_sast", &render_at_120(&app));
}

#[test]
fn module_view_focused_on_recon_with_recent_activity() {
    let mut app = fresh_app();
    app.log.clear();
    app.log(
        "recon:nmap",
        "discovered 5 hosts and 18 services for acme-checkout.com",
    );
    app.log("recon:subdomain", "discovered 7 subdomains");
    app.log("recon", "persisted 3 findings");
    app.handle_command(ShellCommand::Use("recon".to_string()));
    assert_plain_snapshot("module_view_recon_active", &render_at_120(&app));
}

#[test]
fn sast_tasks_view_default() {
    let mut app = fresh_app();
    app.shell_view = ShellView::SastTasks;
    assert_plain_snapshot("sast_tasks_default", &render_at_120(&app));
}

#[test]
fn tune_view_for_focused_module() {
    let mut app = fresh_app();
    app.focused_module = Some("sast".to_string());
    app.shell_view = ShellView::Tune;
    assert_plain_snapshot("tune_view_sast", &render_at_120(&app));
}

#[test]
fn help_view_default() {
    let mut app = fresh_app();
    app.shell_view = ShellView::Help;
    assert_plain_snapshot("help_view_default", &render_at_120(&app));
}

#[test]
fn findings_list_view_with_two_findings() {
    let mut app = fresh_app();
    let mut critical = Finding::new_semgrep(
        "demo.sqli",
        "apps/api/orders.rs",
        142,
        Some(142),
        Severity::Critical,
        "sql injection via order_id concatenation",
    );
    critical.triage = Some(TriageOutcome {
        verdict: TriageVerdict::TruePositive,
        confidence: 0.91,
        rationale: "concatenated input".to_string(),
        cost_usd: 0.0,
    });
    let untriaged = Finding::new_tool(
        "codeql",
        "js/path-injection",
        "apps/web/server.ts",
        301,
        None,
        Severity::High,
        "path traversal in /assets/<file>",
    );
    app.findings = vec![critical, untriaged];
    app.shell_view = ShellView::Findings;
    assert_plain_snapshot("findings_list_two_findings", &render_at_120(&app));
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
        cost_usd: 0.0,
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
    assert_plain_snapshot("module_run_with_findings", &render_at_120(&app));
}

#[test]
fn workspace_view_default() {
    let mut app = fresh_app();
    app.shell_view = ShellView::Workspace;
    assert_plain_snapshot("workspace_view_default", &render_at_120(&app));
}

#[test]
fn knowledge_base_view_default() {
    let mut app = fresh_app();
    app.shell_view = ShellView::KnowledgeBase;
    assert_plain_snapshot("knowledge_base_view_default", &render_at_120(&app));
}

#[test]
fn agent_chat_view_default() {
    let mut app = fresh_app();
    app.shell_view = ShellView::AgentChat;
    assert_plain_snapshot("agent_chat_view_default", &render_at_120(&app));
}

#[test]
fn story_view_default() {
    let mut app = fresh_app();
    app.shell_view = ShellView::Story;
    assert_plain_snapshot("story_view_default", &render_at_120(&app));
}

#[test]
fn options_view_for_sast_scan() {
    let mut app = fresh_app();
    app.shell_view = ShellView::Options(OptionsView {
        tool_name: "sast:scan".to_string(),
        filter: OptionsFilter::Standard,
    });
    assert_plain_snapshot("options_view_for_sast_scan", &render_at_120(&app));
}
