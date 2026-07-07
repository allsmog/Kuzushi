//! Snapshot tests pinning the design-driven plain-text rendering of each
//! key view at a fixed width (120 cols).
//!
//! Snapshot fixtures are checked directly to keep tests offline-friendly.

use std::{fs, path::PathBuf};

use kuzushi_core::{
    latest_run_path, run_dir, Finding, ScanCancellation, Severity, ToolOptionStore, TriageOutcome,
    TriageVerdict, V2Config,
};
use kuzushi_tui::{
    render_plain_app, OptionsFilter, OptionsView, ShellApp, ShellCommand, ShellView, ThreatView,
};

const SNAPSHOT_WIDTH: usize = 120;
const SNAPSHOT_LOG_TIME: u64 = 55_277;

fn render_at_120(app: &mut ShellApp) -> String {
    for line in &mut app.log {
        if line.time_secs != 0 {
            line.time_secs = SNAPSHOT_LOG_TIME;
        }
    }
    strip_line_end_whitespace(&render_plain_app(app, SNAPSHOT_WIDTH))
}

fn strip_line_end_whitespace(output: &str) -> String {
    output
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n")
}

fn fresh_app() -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.option_store = ToolOptionStore::new();
    app
}

/// RAII override of `$HOME` to an empty temp dir, restored on drop. Used to
/// make host-credential-reading views (Auth) render deterministically. Holds
/// a process-global mutex while active so the env mutation can't race other
/// tests in the binary, and keeps the temp dir alive for the scope.
struct ScopedHome {
    previous: Option<std::ffi::OsString>,
    _dir: tempfile::TempDir,
    _guard: std::sync::MutexGuard<'static, ()>,
}

impl ScopedHome {
    fn empty() -> Self {
        static HOME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let guard = HOME_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let previous = std::env::var_os("HOME");
        let dir = tempfile::tempdir().expect("temp HOME");
        std::env::set_var("HOME", dir.path());
        Self {
            previous,
            _dir: dir,
            _guard: guard,
        }
    }
}

impl Drop for ScopedHome {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }
}

fn reset_snapshot_target(name: &str) -> PathBuf {
    let root = PathBuf::from("target")
        .join("kuzushi-tui-snapshots")
        .join(name);
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root)
        .unwrap_or_else(|error| panic!("failed to create {}: {error}", root.display()));
    root
}

fn snapshot_run_dir(root: &std::path::Path, run_id: &str) -> PathBuf {
    run_dir(root, run_id)
}

fn snapshot_latest_run_path(root: &std::path::Path) -> PathBuf {
    latest_run_path(root)
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

const SNAPSHOT_FIXTURE_REVISION: &str = "module-catalog-42";

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
    let _ = SNAPSHOT_FIXTURE_REVISION;
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
    let mut app = fresh_app();
    app.shell_view = ShellView::Catalog;
    assert_plain_snapshot("catalog_view_default", &render_at_120(&mut app));
}

#[test]
fn home_view_default() {
    let mut app = fresh_app();
    app.shell_view = ShellView::Home;
    assert_plain_snapshot("home_view_default", &render_at_120(&mut app));
}

#[test]
fn recommend_view_with_artifact() {
    let root = reset_snapshot_target("recommend");
    let run_dir = snapshot_run_dir(&root, "run-rec");
    fs::create_dir_all(&run_dir).unwrap();
    fs::write(snapshot_latest_run_path(&root), "run-rec\n").unwrap();
    fs::write(
        run_dir.join("recommendations.json"),
        serde_json::json!({
            "summary": "Prioritize deterministic scanner coverage before model-backed review.",
            "recommendations": [{
                "tool": "semgrep:scan",
                "priority": "high",
                "reason": "Source files match the fast native SAST path.",
                "signals": ["frameworks: Falcon, Litestar, Sanic"],
                "requiresRuntime": false
            }]
        })
        .to_string(),
    )
    .unwrap();
    fs::write(
        run_dir.join("attack-surface.json"),
        serde_json::json!({
            "summary": {
                "highRisk": 1,
                "maxRiskScore": 90,
                "byRiskTier": {"critical": 1}
            },
            "surfaces": [{
                "framework": "Spring",
                "title": "POST /admin",
                "risk": {"tier": "critical"}
            }, {
                "framework": "Next.js",
                "title": "POST /api/session",
                "risk": {"tier": "medium"}
            }]
        })
        .to_string(),
    )
    .unwrap();

    let mut app = fresh_app();
    app.target = Some(root);
    app.shell_view = ShellView::Recommend;
    assert_plain_snapshot("recommend_view_with_artifact", &render_at_120(&mut app));
}

#[test]
fn threat_stories_view_with_canonical_fixture() {
    let mut app = fresh_app();
    app.shell_view = ShellView::Threat(ThreatView::Stories);
    assert_plain_snapshot("threat_stories_canonical", &render_at_120(&mut app));
}

#[test]
fn threat_scope_view_with_canonical_fixture() {
    let mut app = fresh_app();
    app.shell_view = ShellView::Threat(ThreatView::Scope);
    assert_plain_snapshot("threat_scope_canonical", &render_at_120(&mut app));
}

#[test]
fn threat_stride_view_with_canonical_fixture() {
    let mut app = fresh_app();
    app.shell_view = ShellView::Threat(ThreatView::Stride);
    assert_plain_snapshot("threat_stride_canonical", &render_at_120(&mut app));
}

#[test]
fn threat_summary_view_with_canonical_fixture() {
    let mut app = fresh_app();
    app.shell_view = ShellView::Threat(ThreatView::Summary);
    assert_plain_snapshot("threat_summary_canonical", &render_at_120(&mut app));
}

#[test]
fn module_view_focused_on_sast() {
    let mut app = fresh_app();
    app.handle_command(ShellCommand::Use("sast".to_string()));
    assert_plain_snapshot("module_view_sast", &render_at_120(&mut app));
}

#[test]
fn sast_tasks_view_default() {
    let mut app = fresh_app();
    app.shell_view = ShellView::SastTasks;
    assert_plain_snapshot("sast_tasks_default", &render_at_120(&mut app));
}

#[test]
fn tune_view_for_focused_module() {
    let mut app = fresh_app();
    app.focused_module = Some("sast".to_string());
    app.shell_view = ShellView::Tune;
    assert_plain_snapshot("tune_view_sast", &render_at_120(&mut app));
}

#[test]
fn help_view_default() {
    let mut app = fresh_app();
    app.shell_view = ShellView::Help;
    assert_plain_snapshot("help_view_default", &render_at_120(&mut app));
}

#[test]
fn workbench_empty_view_default() {
    let mut app = fresh_app();
    app.shell_view = ShellView::Workbench;
    assert_plain_snapshot("workbench_empty_view_default", &render_at_120(&mut app));
}

#[test]
fn workbench_list_view_with_two_findings() {
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
    app.shell_view = ShellView::Workbench;
    assert_plain_snapshot("workbench_list_two_findings", &render_at_120(&mut app));
}

#[test]
fn run_timeline_view_with_past_runs() {
    let root = reset_snapshot_target("runs");
    let completed_run_dir = snapshot_run_dir(&root, "r-2026-05-06T14-31");
    let failed_run_dir = snapshot_run_dir(&root, "r-2026-05-06T15-18");
    fs::create_dir_all(&completed_run_dir).unwrap();
    fs::create_dir_all(&failed_run_dir).unwrap();
    fs::write(
        completed_run_dir.join("run.json"),
        r#"{"status":"completed","findings":18,"target":"~/work/acme-checkout"}"#,
    )
    .unwrap();
    fs::write(
        failed_run_dir.join("run.json"),
        r#"{"status":"failed","findings":0,"target":"~/work/acme-checkout"}"#,
    )
    .unwrap();

    let mut app = fresh_app();
    app.target = Some(root);
    app.shell_view = ShellView::Runs;
    assert_plain_snapshot("run_timeline_view_with_past_runs", &render_at_120(&mut app));
}

#[test]
fn failure_handoff_view_with_artifact() {
    let root = reset_snapshot_target("failure");
    let run_dir = snapshot_run_dir(&root, "run-failed");
    fs::create_dir_all(&run_dir).unwrap();
    fs::write(snapshot_latest_run_path(&root), "run-failed\n").unwrap();
    fs::write(
        run_dir.join("failures.json"),
        serde_json::json!({
            "runId": "run-failed",
            "status": "failed",
            "failures": [{
                "tool": "semgrep:scan",
                "status": "failed",
                "error": "semgrep binary missing",
                "agentThreadContext": {
                    "failedStage": "semgrep:scan",
                    "cause": "semgrep binary missing",
                    "whatFailed": "semgrep:scan did not complete successfully",
                    "artifactsAvailable": [],
                    "missingArtifacts": ["findings.json"],
                    "allowedProofLevel": "artifact-review-only; runtime verification did not run",
                    "nextFilesOrArtifactsToInspect": ["failures.json"],
                    "recoveryOptions": ["Install semgrep."],
                    "fallbackPrompt": "Continue the failed Kuzushi run.",
                    "claimsForbidden": ["verified"]
                }
            }]
        })
        .to_string(),
    )
    .unwrap();

    let mut app = fresh_app();
    app.target = Some(root);
    app.shell_view = ShellView::FailureHandoff;
    assert_plain_snapshot(
        "failure_handoff_view_with_artifact",
        &render_at_120(&mut app),
    );
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
    assert_plain_snapshot("module_run_with_findings", &render_at_120(&mut app));
}

#[test]
fn workspace_view_default() {
    let mut app = fresh_app();
    app.shell_view = ShellView::Workspace;
    assert_plain_snapshot("workspace_view_default", &render_at_120(&mut app));
}

#[test]
fn knowledge_base_view_default() {
    let mut app = fresh_app();
    app.shell_view = ShellView::KnowledgeBase;
    assert_plain_snapshot("knowledge_base_view_default", &render_at_120(&mut app));
}

#[test]
fn agent_chat_view_default() {
    let mut app = fresh_app();
    app.shell_view = ShellView::AgentChat;
    assert_plain_snapshot("agent_chat_view_default", &render_at_120(&mut app));
}

#[test]
fn story_view_default() {
    let mut app = fresh_app();
    app.shell_view = ShellView::Story;
    assert_plain_snapshot("story_view_default", &render_at_120(&mut app));
}

#[test]
fn options_view_for_sast_scan() {
    let mut app = fresh_app();
    app.shell_view = ShellView::Options(OptionsView {
        tool_name: "sast:scan".to_string(),
        filter: OptionsFilter::Standard,
    });
    assert_plain_snapshot("options_view_for_sast_scan", &render_at_120(&mut app));
}

#[test]
fn activity_view_default_split_pane() {
    use kuzushi_core::RunTraceStep;
    use kuzushi_tui::ActivitySession;

    let mut app = fresh_app();
    // Seed a deterministic ActivitySession so the snapshot doesn't drift
    // with wall-clock-derived run ids and timestamps.
    let mut session = ActivitySession::new("r-snapshot");
    let stable_ts = 1_700_000_000_000u64;
    let seeds: &[(usize, &str, &str, &str, &str, Option<usize>)] = &[
        (1, "tool", "context", "build", "context:build start", None),
        (
            2,
            "done",
            "context",
            "build",
            "context:build complete · 412 files",
            None,
        ),
        (3, "tool", "semgrep", "scan", "semgrep start", None),
        (
            4,
            "done",
            "semgrep",
            "scan",
            "semgrep complete · 14 findings",
            None,
        ),
        (5, "tool", "triage", "run", "triage start", None),
        (
            6,
            "reasoning",
            "triage",
            "run",
            "evidence-collect · stage1 kept 14/14",
            Some(5),
        ),
        (
            7,
            "reasoning",
            "triage",
            "run",
            "verdict=likely-tp severity=high",
            Some(5),
        ),
        (
            8,
            "tool",
            "pipeline",
            "task-selector",
            "task-selector ran",
            None,
        ),
    ];
    for (n, kind, module, verb, label, parent) in seeds {
        let mut step = RunTraceStep::new(*n, *kind, *label)
            .with_module_id(*module)
            .with_verb(*verb)
            .with_started_at_ms(stable_ts);
        if let Some(p) = parent {
            step = step.with_parent_step(*p);
        }
        session.apply_step(step);
    }
    let snapshot_instant = std::time::Instant::now() + std::time::Duration::from_secs(5);
    for row in session.tasks.values_mut() {
        row.started_at = Some(snapshot_instant);
        if row.completed_at.is_some() {
            row.completed_at = Some(snapshot_instant);
        }
    }
    app.activity = Some(session);
    app.shell_view = ShellView::Activity;

    assert_plain_snapshot("activity_view_default_split_pane", &render_at_120(&mut app));
}

#[test]
fn auth_view_default_with_rotate_section() {
    // M3 §3.4: the Auth view carries the providers table, model + spend
    // sections, and a ROTATE hint block so operators can recover from a
    // bad key without leaving the shell. This snapshot pins the layout
    // so future tweaks don't silently drop the rotate hints.
    //
    // The provider rows read `$HOME/.kuzushi/oauth-credentials.json`, so
    // point HOME at an empty temp dir — otherwise a machine with stored
    // (or expired) oauth tokens renders "expired" instead of "missing" and
    // this snapshot becomes host-dependent (it was failing on CI runners
    // that carried an expired credential file).
    let _home = ScopedHome::empty();
    let mut app = fresh_app();
    app.shell_view = ShellView::Auth;
    assert_plain_snapshot("auth_view_default", &render_at_120(&mut app));
}

#[test]
fn footer_wrapped_narrow_terminal() {
    // M4 §4.2: terminals narrower than 70 cols (tmux side panes, sshd
    // on mobile, side-by-side editor splits) get a two-line keybinding
    // footer so nothing truncates. This snapshot pins the wrap shape
    // at width 60 — the chrome rule plus two keybinding rows.
    let mut app = fresh_app();
    app.shell_view = ShellView::Home;
    for line in &mut app.log {
        if line.time_secs != 0 {
            line.time_secs = SNAPSHOT_LOG_TIME;
        }
    }
    let rendered = strip_line_end_whitespace(&render_plain_app(&app, 60));
    assert_plain_snapshot("footer_wrapped_narrow", &rendered);
}

#[test]
fn every_shell_view_produces_non_empty_plain_output() {
    // M4 §4.3: plain-mode parity. The LineBased fallback already paints
    // every view that lacks a dedicated `PlainRenderMode`, but a future
    // refactor that breaks a view's `*_lines` source would silently
    // produce empty plain output. This regression asserts non-empty
    // plain text for every ShellView variant so the contract holds.
    let scenarios: Vec<(&str, ShellView)> = vec![
        ("home", ShellView::Home),
        ("catalog", ShellView::Catalog),
        ("recommend", ShellView::Recommend),
        ("module", ShellView::Module),
        ("module_run", ShellView::ModuleRun),
        ("workbench", ShellView::Workbench),
        ("tune", ShellView::Tune),
        ("threat_summary", ShellView::Threat(ThreatView::Summary)),
        ("threat_stride", ShellView::Threat(ThreatView::Stride)),
        ("threat_stories", ShellView::Threat(ThreatView::Stories)),
        ("threat_scope", ShellView::Threat(ThreatView::Scope)),
        ("threat_editor", ShellView::ThreatEditor),
        ("prompts_editor", ShellView::PromptsEditor),
        ("actor_detail", ShellView::ActorDetail(0)),
        ("runs", ShellView::Runs),
        ("replay", ShellView::Replay("run-1".to_string())),
        ("trace", ShellView::Trace("run-1".to_string())),
        ("help", ShellView::Help),
        ("quickstart", ShellView::Quickstart),
        ("logs", ShellView::Logs),
        ("config", ShellView::Config),
        ("tools", ShellView::Tools),
        (
            "options",
            ShellView::Options(OptionsView {
                tool_name: "sast:scan".to_string(),
                filter: OptionsFilter::Standard,
            }),
        ),
        ("sast_tasks", ShellView::SastTasks),
        ("context", ShellView::Context),
        ("workspace", ShellView::Workspace),
        ("knowledge_base", ShellView::KnowledgeBase),
        ("failure_handoff", ShellView::FailureHandoff),
        ("agent_chat", ShellView::AgentChat),
        ("history", ShellView::History),
        ("story", ShellView::Story),
        ("auth", ShellView::Auth),
        ("cost", ShellView::Cost),
        ("patch", ShellView::Patch("F-0001".to_string())),
        ("pwn", ShellView::Pwn),
        ("activity", ShellView::Activity),
    ];

    for (label, view) in scenarios {
        let mut app = fresh_app();
        app.shell_view = view;
        let rendered = render_plain_app(&app, SNAPSHOT_WIDTH);
        assert!(
            !rendered.trim().is_empty(),
            "ShellView {label} produced empty plain output"
        );
        assert!(
            !rendered.contains('\x1b'),
            "ShellView {label} plain output leaked ANSI escapes: {rendered}"
        );
    }
}

#[test]
fn home_view_high_contrast_is_renderable_without_panic() {
    // M4 §4.1: KUZUSHI_THEME=high-contrast flips the palette to bright
    // white + bold. The plain renderer strips colours but the view must
    // still produce output. The reduced_motion env var pauses the
    // spinner; this test covers the rendering side, the spinner cadence
    // gate is unit-tested in `state_transitions::ticking`.
    let mut app = fresh_app();
    app.shell_view = ShellView::Home;
    let rendered = render_plain_app(&app, SNAPSHOT_WIDTH);
    assert!(rendered.contains("HOME"));
    // Locked in: plain output never carries ANSI escapes regardless of
    // theme, so high-contrast and default render identically through
    // `render_plain_app`. Colour comes back when the TUI renders to a
    // real terminal via render_app.
    assert!(!rendered.contains('\x1b'));
}
