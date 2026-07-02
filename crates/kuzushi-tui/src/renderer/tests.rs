use kuzushi_core::{
    Finding, FindingEvidence, OptionScope, OptionTarget, ScanCancellation, Severity,
    StaticProofState, TriageOutcome, TriageVerdict, V2Config,
};
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::Terminal;

use crate::commands::{shell_command_specs, shell_help_examples, ShellCommandCategory};
use crate::ui_view_models::{
    catalog_model, context_snapshot_relative_path, prompt_text, threat_model_relative_path,
    threat_scope_model_from_doc, threat_story_model_from_doc, threat_stride_rollup_from_doc,
    ui_latest_run_path, ui_run_artifact_relative_path, ui_run_dir, view_status_segment,
    ModuleRunStatusKind, RoutingMode, SeverityTone, ThreatStrideTone,
};

use super::*;

fn context_snapshot_fixture_path() -> std::path::PathBuf {
    kuzushi_core::context_snapshot_path("")
}

fn target_context_snapshot_path(target: &std::path::Path) -> std::path::PathBuf {
    kuzushi_core::context_snapshot_path(target)
}

#[test]
fn kuzushi_theme_uses_blue_cyan_cockpit_accents() {
    assert_eq!(
        theme::T_ACCENT,
        ratatui::prelude::Color::Rgb(0x7f, 0xb8, 0xff)
    );
    assert_eq!(
        theme::T_LABEL,
        ratatui::prelude::Color::Rgb(0xa6, 0xcd, 0xff)
    );
}

#[test]
fn renders_ink_style_shell_without_box_dashboard() {
    let backend = TestBackend::new(96, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Home;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("HOME"));
    assert!(rendered.contains("run artifacts"));
    assert!(rendered.contains("modules"));
    assert!(rendered.contains("recommend"));
    assert!(rendered.contains("kuzushi>"));
    assert!(rendered.contains("Tab complete"));
    assert!(rendered.contains("modules browse"));
    assert!(!rendered.contains("command log"));
    assert!(!rendered.contains("┌"));
    assert!(!rendered.contains("v2"));
}

#[test]
fn retry_gate_card_renders_failed_tasks_and_fix() {
    let backend = TestBackend::new(100, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.advisory.pending_retry = Some(crate::app::PendingRetry {
        tasks: vec![crate::app::FailedPlanningTask {
            task: crate::app::PlanningTaskId::BuildCodePropertyGraph,
            error: "java heap OOM".to_string(),
            adjustment: Some(crate::app::RetryAdjustment::RaiseHeap { heap_mb: 12288 }),
            blocked: vec![crate::app::PlanningTaskId::HuntTaint],
        }],
    });

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    // The retry section must paint its own card (correct handler index).
    assert!(rendered.contains("RETRY"));
    assert!(rendered.contains("cpg:build"));
    assert!(rendered.contains("12288"));
    assert!(rendered.contains("retry"));
}

fn planning_row_fixture(
    id: crate::app::PlanningTaskId,
    state: crate::app::PlanningArtifactState,
) -> crate::app::PlanningTaskRow {
    crate::app::PlanningTaskRow {
        id,
        label: id.label(),
        tool_name: id.tool_name(),
        artifact_path: std::path::PathBuf::from("/dev/null"),
        artifact_state: state,
        artifact_modified: None,
        model_backed: id.is_model_backed(),
        required_cli: None,
        cli_available: true,
    }
}

#[test]
fn planning_picker_announces_prior_state_and_plain_language_outcomes() {
    use crate::app::{PlanningArtifactState, PlanningTaskId, WorkflowPhase};

    let backend = TestBackend::new(110, 44);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    let dir = tempfile::tempdir().unwrap();
    app.target = Some(dir.path().to_path_buf());
    app.workflow_phase = Some(WorkflowPhase::Map);
    app.findings.push(Finding::new_tool(
        "demo",
        "demo.rule",
        "src/lib.rs",
        7,
        None,
        Severity::Medium,
        "prior finding",
    ));
    app.planning_tasks = vec![
        planning_row_fixture(
            PlanningTaskId::GatherRepoContext,
            PlanningArtifactState::Cached,
        ),
        planning_row_fixture(PlanningTaskId::BuildXRay, PlanningArtifactState::Missing),
    ];
    app.planning_selected = [PlanningTaskId::GatherRepoContext, PlanningTaskId::BuildXRay]
        .into_iter()
        .collect();
    app.shell_view = ShellView::PlanningPicker;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    // Prior state is announced up front, with counts the operator can verify.
    assert!(
        rendered.contains("Resuming"),
        "prior-state banner: {rendered}"
    );
    assert!(rendered.contains("cached artifact"));
    assert!(rendered.contains("1 finding"));
    // Ambiguous [x]/[~]/[ ] glyphs are gone; outcomes read as words + a legend.
    assert!(rendered.contains("OUTCOME"));
    assert!(rendered.contains("RUN"));
    assert!(rendered.contains("REUSE"));
    assert!(!rendered.contains("[~]"));
    // Enter is spelled out, not left to guesswork.
    assert!(
        rendered.contains("Enter: run 1 new step"),
        "enter summary: {rendered}"
    );
}

#[test]
fn plain_retry_gate_explains_y_n_intercept() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.advisory.pending_retry = Some(crate::app::PendingRetry {
        tasks: vec![crate::app::FailedPlanningTask {
            task: crate::app::PlanningTaskId::BuildCodePropertyGraph,
            error: "java heap OOM".to_string(),
            adjustment: Some(crate::app::RetryAdjustment::RaiseHeap { heap_mb: 12288 }),
            blocked: vec![crate::app::PlanningTaskId::HuntTaint],
        }],
    });

    let rendered = render_plain_app(&app, 100);

    assert!(rendered.contains("RETRY"));
    assert!(rendered.contains("y/Enter retry"));
    assert!(rendered.contains("n/Esc skip"));
    assert!(rendered.contains("cpg:build"));
    assert!(rendered.contains("12288"));
}

#[test]
fn compact_alias_uses_kz_prompt_brand() {
    assert_eq!(prompt_text("kz", RoutingMode::Shell, None), "kz> ");
    assert_eq!(
        prompt_text("kz", RoutingMode::Module, Some("sast")),
        "kz/sast> "
    );
    assert_eq!(
        prompt_text("kz", RoutingMode::Run, Some("sast")),
        "kz/sast/run> "
    );
}

#[test]
fn home_first_run_state_names_real_artifact_commands() {
    let backend = TestBackend::new(80, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Home;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("HOME"));
    assert!(rendered.contains("run artifacts"));
    assert!(rendered.contains("scan ."));
    assert!(rendered.contains("findings"));
    assert!(rendered.contains("modules"));
    assert!(rendered.contains("recommend"));
    assert!(rendered.contains("quickstart"));
    assert!(!rendered.contains("./repo"));
    assert!(!rendered.contains("┌"));
}

#[test]
fn home_view_renders_latest_run_artifact_rail() {
    let tmp = tempfile::tempdir().unwrap();
    let run_dir = ui_run_dir(Some(tmp.path()), "run-1");
    std::fs::create_dir_all(&run_dir).unwrap();
    std::fs::write(ui_latest_run_path(Some(tmp.path())), "run-1\n").unwrap();
    std::fs::write(run_dir.join("run.json"), r#"{"status":"completed"}"#).unwrap();
    std::fs::write(run_dir.join("context.json"), r#"{"languages":["rust"]}"#).unwrap();
    std::fs::write(run_dir.join("findings.json"), r#"{"status": "skipped"}"#).unwrap();
    std::fs::write(
        run_dir.join("attack-surface.json"),
        serde_json::json!({
            "status": "partial",
            "summary": {
                "highRisk": 2,
                "maxRiskScore": 100,
                "byRiskTier": {"critical": 1, "high": 1}
            },
            "surfaces": [{
                "framework": "Spring",
                "title": "Command execution boundary",
                "risk": {"tier": "critical"}
            }, {
                "framework": "Next.js",
                "title": "POST /api/session",
                "risk": {"tier": "medium"}
            }, {
                "framework": "Rails",
                "title": "Background job boundary",
                "risk": {"tier": "high"}
            }]
        })
        .to_string(),
    )
    .unwrap();
    std::fs::write(run_dir.join("threat-model.json"), r#"{"status":"failed"}"#).unwrap();

    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(tmp.path().to_path_buf());
    app.shell_view = ShellView::Home;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("HOME"));
    assert!(rendered.contains("run-1"));
    assert!(rendered.contains("completed"));
    assert!(rendered.contains("surface risk"));
    assert!(rendered.contains("2 high/critical"));
    assert!(rendered.contains("critical=1"));
    assert!(rendered.contains("frameworks Next.js=1, Rails=1, Spring=1"));
    assert!(rendered.contains("ctx"));
    assert!(rendered.contains("✓"));
    assert!(rendered.contains("recorded"));
    assert!(rendered.contains("findings"));
    assert!(rendered.contains("○"));
    assert!(rendered.contains("placeholder"));
    assert!(rendered.contains("⚠"));
    assert!(rendered.contains("failed"));
    assert!(rendered.contains("■"));
    assert!(rendered.contains("missing"));
    assert!(rendered.contains("◆"));
    assert!(rendered.contains("partial"));
}

#[test]
fn catalog_default_is_grouped_at_normal_width() {
    let backend = TestBackend::new(120, 60);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Catalog;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("MODULES"));
    assert!(rendered.contains("▸ NEXT"));
    assert!(rendered.contains("OFFENSE"));
    assert!(rendered.contains("INTEL"));
    assert!(rendered.contains("GOVERNANCE"));
    assert!(rendered.contains("DEFENSE"));
    assert!(rendered.contains("sast"));
    assert!(!rendered.contains("Start here"));
    assert!(!rendered.contains("[!] no target selected"));
}

#[test]
fn catalog_default_keeps_quickstart_fallback_on_tight_width() {
    let backend = TestBackend::new(80, 16);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Catalog;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("MODULES"));
    assert!(rendered.contains("Start here"));
    assert!(rendered.contains("context build"));
    assert!(rendered.contains("scan ."));
    assert!(rendered.contains("findings"));
    assert!(!rendered.contains("OFFENSE"));
    assert!(!rendered.contains("agentic-sast"));
}

#[test]
fn quickstart_follows_doctor_context_scan_findings_report_path() {
    let backend = TestBackend::new(80, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Quickstart;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let buffer = terminal.backend().buffer();
    let rendered = format!("{:?}", buffer);

    for expected in [
        "Operator path",
        "kuzushi doctor",
        "context build",
        ".kuzushi/context-snapshot.json",
        "options sast:scan",
        "scan .",
        "findings",
        "proof state",
        "workspace export",
        "kuzushi pr-comment",
    ] {
        assert!(
            rendered.contains(expected),
            "missing {expected}: {rendered}"
        );
    }
    assert!(rendered.find("kuzushi doctor").unwrap() < rendered.find("context build").unwrap());
    assert!(rendered.find("context build").unwrap() < rendered.find("options sast:scan").unwrap());
    assert!(rendered.find("options sast:scan").unwrap() < rendered.find("scan .").unwrap());
    for y in 0..22 {
        let row = buffer_row_text(buffer, 80, y);
        assert!(
            row.chars().count() <= 80,
            "row exceeded 80 columns: {row:?}"
        );
    }
    assert!(!rendered.contains("┌"));
}

#[test]
fn renders_actionable_empty_states_at_80_columns() {
    // Each empty-state surface advertises a concrete next step,
    // matching `design/mockups/empty-states.jsx::panel` (`∅` glyph
    // + label + indented muted explanation + `▸` CTA rows).
    for (view, expected) in [
        (ShellView::Runs, "no run timeline entries"),
        (ShellView::Workspace, "no workspace selected"),
    ] {
        let backend = TestBackend::new(80, 18);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        let runs_target = tempfile::tempdir().unwrap();
        let is_runs = matches!(view, ShellView::Runs);
        app.shell_view = view;
        if is_runs {
            app.target = Some(runs_target.path().to_path_buf());
        }

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains(expected), "missing {expected}");
        if is_runs {
            assert!(rendered.contains(".kuzushi/runs/<id>"), "{rendered}");
        }
        // These line-based empty states must stay free of nested boxes (the
        // bordered command center is the only box-drawing primary surface).
        assert!(!rendered.contains("┌"), "{expected} drew a box");
    }
}

#[test]
fn renders_long_prompt_on_single_row() {
    let backend = TestBackend::new(40, 12);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.input = "scan ./a/very/long/path/that/should/not/wrap".to_string();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("kuzushi>"));
    assert!(!rendered.contains("prompt"));
}

#[test]
fn keeps_command_log_directly_above_bottom_prompt_at_80_columns() {
    let backend = TestBackend::new(80, 12);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.log(
        "error",
        "scanner failed while reading src/really/long/path/that/must/not_overlap.rs",
    );
    app.log(
        "result",
        "next action: inspect configuration and rerun scan with a narrower target",
    );
    app.input = "run sast:scan {\"severity\":[\"high\"],\"triage\":true}".to_string();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let buffer = terminal.backend().buffer();
    let prompt_row = buffer_row_text(buffer, 80, 11);
    let log_row = buffer_row_text(buffer, 80, 10);

    assert!(prompt_row.trim_start().starts_with("kuzushi>"));
    assert!(prompt_row.contains("triage"));
    assert!(!prompt_row.contains("result"));
    assert!(log_row.contains("result"));
    assert!(!log_row.contains("kuzushi>"));
    assert!(!format!("{:?}", buffer).contains("┌"));
}

#[test]
fn renders_exit_commands_before_closing() {
    for command in ["/exit", "exit"] {
        let backend = TestBackend::new(80, 12);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);

        app.submit_line(command);
        assert!(app.should_quit, "{command} should request shell shutdown");

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let buffer = terminal.backend().buffer();
        let command_row = buffer_row_text(buffer, 80, 9);
        let exit_row = buffer_row_text(buffer, 80, 10);
        let prompt_row = buffer_row_text(buffer, 80, 11);

        assert!(
            command_row.contains(command),
            "{command} should remain visible in the transcript"
        );
        assert!(exit_row.contains("exit requested; closing shell"));
        assert!(prompt_row.trim_start().starts_with("kuzushi>"));
    }
}

#[test]
fn replay_and_trace_surfaces_reuse_current_finding_aliases() {
    for view in [
        ShellView::Replay("run-1".to_string()),
        ShellView::Trace("run-1".to_string()),
    ] {
        let backend = TestBackend::new(80, 18);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        let mut finding =
            Finding::new_semgrep("demo.rule", "src/app.ts", 8, None, Severity::High, "sink");
        finding.fingerprint = "aaaa1111".to_string();
        app.findings = vec![finding];
        app.shell_view = view;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("ALIASES"));
        assert!(rendered.contains("F-0001"));
        assert!(rendered.contains("aaaa1111"));
    }
}

#[test]
fn renders_threat_view_navigation() {
    let backend = TestBackend::new(120, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Threat(ThreatView::Stride);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("STRIDE"));
    assert!(rendered.contains("Spoofing"));
}

#[test]
fn renders_pending_threat_patch_card() {
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_pending_threat_patch(crate::app::ThreatPatch {
        goal: "regen".to_string(),
        summary: "add admin trust zone".to_string(),
        patch: serde_json::json!({"trustZones":{"admin":"isolated"}}),
        unsupported: vec!["manual review required".to_string()],
    });

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("THREAT PATCH"));
    assert!(rendered.contains("add admin trust zone"));
    assert!(rendered.contains("1 top-level key"));
    assert!(rendered.contains("/threats apply"));
    assert!(rendered.contains("/threats reject"));
    assert!(!rendered.contains("┌"));
}

#[test]
fn renders_expanded_catalog_readably_on_narrow_terminal() {
    let backend = TestBackend::new(58, 32);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.handle_command(crate::commands::ShellCommand::Modules);
    app.findings = (0..82)
        .map(|index| {
            Finding::new_semgrep(
                format!("demo.rule.{index}"),
                "src/app.ts",
                index + 1,
                None,
                Severity::Medium,
                "demo finding",
            )
        })
        .collect();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("82 findings"));
    assert!(rendered.contains("semgrep"));
    // Category divider embeds the section blurb on the rule line — see
    // `category_divider` and `design/mockups/catalog.jsx::catHead`. Narrow
    // terminals truncate, so assert on the shortest blurb word that
    // survives an 58-col render: "OFFENSE" itself.
    assert!(rendered.contains("OFFENSE"));
    assert!(!rendered.contains("module context-lite"));
    assert!(!rendered.contains("command log"));
}

#[test]
fn expanded_catalog_uses_design_sections_without_dag_column() {
    let backend = TestBackend::new(120, 36);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.handle_command(crate::commands::ShellCommand::Modules);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("MODULES"));
    assert!(rendered.contains("▸ NEXT"));
    assert!(rendered.contains("OFFENSE"));
    assert!(rendered.contains("sast"));
    assert!(!rendered.contains("dag"));
    assert!(!rendered.contains("DAG"));
}

#[test]
fn catalog_next_hint_steers_through_context_then_findings() {
    let mut app = ShellApp::new(V2Config::default(), None);

    // Default fresh app: no context snapshot built.
    assert!(
        catalog_model(&app)
            .collapsed
            .next_hint
            .contains("context build"),
        "fresh app should suggest context build"
    );

    // After context exists but no findings: first-finding scan hint.
    app.context_view.exists = true;
    let hint = catalog_model(&app).collapsed.next_hint;
    assert!(
        hint.contains("First finding") || hint.contains("scan"),
        "ctx-built no-findings should suggest scanning, got: {hint}"
    );

    // With non-critical findings: drill-in suggestion.
    let medium = Finding::new_semgrep("demo.rule", "src/a.rs", 1, None, Severity::Medium, "x");
    app.findings = vec![medium];
    let hint = catalog_model(&app).collapsed.next_hint;
    assert!(hint.contains("findings"), "got: {hint}");
    assert!(hint.contains("triage"), "got: {hint}");
    assert!(hint.contains("threats regen"), "got: {hint}");
    assert!(!hint.contains("threats build"), "got: {hint}");

    // With a critical finding: open-by-alias suggestion.
    let critical = Finding::new_semgrep("demo.crit", "src/b.rs", 2, None, Severity::Critical, "y");
    app.findings.push(critical);
    let hint = catalog_model(&app).collapsed.next_hint;
    assert!(hint.contains("open F-"), "got: {hint}");
}

#[test]
fn module_playbooks_name_supported_run_and_scan_commands() {
    let cases = [
        ("context", "context build", "run build"),
        ("threat-model", "threats regen", "threats build"),
        ("sast", "scan runs configured scanners", "run . or scan"),
        ("cargo-audit", "RustSec advisories", "tool-specific options"),
        ("agentic-sast", "run agentic-sast:scan", "run scan"),
    ];
    for (module, required, stale) in cases {
        let primary_tool = match module {
            "context" => "context:build",
            "threat-model" => "threat-model:build",
            "sast" => "sast:scan",
            "cargo-audit" => "cargo-audit:scan",
            "agentic-sast" => "agentic-sast:scan",
            _ => "demo:tool",
        };
        let text = module_playbook_lines(module, primary_tool, 120)
            .into_iter()
            .map(|line| line_text(&line))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            text.contains(required),
            "{module} missing {required}: {text}"
        );
        assert!(
            !text.contains(stale),
            "{module} still shows {stale}: {text}"
        );
        assert!(
            text.contains(&format!("dispatches {primary_tool}")),
            "{module} does not explain run . resolution: {text}"
        );
        assert!(
            text.contains("terminal: kuzushi --target . run"),
            "{module} does not distinguish terminal run syntax: {text}"
        );
        assert!(
            text.contains("options .") || text.contains("options sast:scan"),
            "{module} does not point at the options view: {text}"
        );
        if module == "sast" {
            assert!(
                text.contains("options sast:scan"),
                "{module} does not name scan tuning command: {text}"
            );
            assert!(
                text.contains(".kuzushi/v2/findings.sqlite3"),
                "{module} does not name the findings DB artifact: {text}"
            );
        }
        if module == "context" {
            assert!(
                text.contains(context_snapshot_relative_path()),
                "{module} does not name the shared context snapshot label: {text}"
            );
        }
        if module == "threat-model" {
            assert!(
                text.contains(&threat_model_relative_path()),
                "{module} does not name the shared threat-model label: {text}"
            );
        }
    }

    let codeql_text = module_playbook_lines("codeql", "codeql:scan", 120)
        .into_iter()
        .map(|line| line_text(&line))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        codeql_text.contains(".kuzushi/v2/findings.sqlite3 and optional SARIF"),
        "codeql does not name findings DB plus optional SARIF: {codeql_text}"
    );
}

#[test]
fn spinner_cycles_through_six_frames_by_log_length() {
    let frames: Vec<&str> = (0..12)
        .map(|tick| run_state_glyph(ModuleRunStatusKind::Running, tick))
        .collect();
    // First 6 ticks cover all 6 frames
    let unique: std::collections::BTreeSet<&&str> = frames.iter().take(6).collect();
    assert_eq!(
        unique.len(),
        6,
        "first 6 frames should be unique: {frames:?}"
    );
    // Frame at tick N == frame at tick N+6 (cycle period)
    for tick in 0..6 {
        assert_eq!(
            frames[tick],
            frames[tick + 6],
            "spinner should repeat every 6 ticks"
        );
    }
}

#[test]
fn spinner_shows_static_glyph_when_scan_idle_or_done() {
    assert_eq!(run_state_glyph(ModuleRunStatusKind::Idle, 0), "●");
    assert_eq!(run_state_glyph(ModuleRunStatusKind::Idle, 99), "●");
    assert_eq!(
        run_state_glyph(ModuleRunStatusKind::Running, 0),
        SPINNER_FRAMES[0]
    );
    assert_eq!(run_state_glyph(ModuleRunStatusKind::Done, 4), "✓");
}

#[test]
fn module_run_body_ends_with_streaming_cursor_when_scan_active() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.scan = Some(crate::app::ScanPanelState {
        run_id: Some("run-abc".to_string()),
        target: std::path::PathBuf::from("./demo"),
        stage: "scanning".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    });
    app.shell_view = ShellView::ModuleRun;
    let area = Rect::new(0, 0, 120, 30);
    let lines = module_run_lines(&app, area);
    let last = lines.last().expect("expected non-empty body");
    let last_text: String = last.spans.iter().map(|s| s.content.as_ref()).collect();
    // The cursor line is " " + a single styled-block " ", so two visible cells.
    assert_eq!(
        last_text, "  ",
        "expected streaming cursor line at end while scan running, got {last_text:?}"
    );
    // Sanity: confirm a styled span with primary bg exists on that line.
    let has_inverse = last
        .spans
        .iter()
        .any(|sp| sp.style.bg.is_some() && sp.content.as_ref() == " ");
    assert!(
        has_inverse,
        "streaming cursor should be a styled background cell"
    );
}

#[test]
fn module_run_body_omits_streaming_cursor_when_idle() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::ModuleRun;
    let area = Rect::new(0, 0, 120, 30);
    let lines = module_run_lines(&app, area);
    // No scan → no streaming cursor expected.
    for line in &lines {
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        let has_cursor = line
            .spans
            .iter()
            .any(|sp| sp.style.bg.is_some() && sp.content.as_ref() == " ");
        assert!(
            !has_cursor || text.trim() != "",
            "unexpected streaming cursor while idle: {text:?}"
        );
    }
}

#[test]
fn module_run_findings_preview_uses_projected_finding_rows() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::ModuleRun;
    let mut triaged = Finding::new_semgrep(
        "demo.sql",
        "src/search.ts",
        12,
        Some(14),
        Severity::High,
        "SQL injection in search",
    );
    triaged.triage = Some(TriageOutcome {
        verdict: TriageVerdict::TruePositive,
        confidence: 0.91,
        rationale: "source and sink are linked".to_string(),
        cost_usd: 0.0,
    });
    app.findings = vec![
        triaged,
        Finding::new_tool(
            "codeql",
            "js/path-injection",
            "src/files.ts",
            22,
            None,
            Severity::Medium,
            "Path traversal candidate",
        ),
    ];

    let rendered = module_run_lines(&app, Rect::new(0, 0, 120, 40))
        .iter()
        .map(line_text)
        .collect::<Vec<_>>()
        .join("\n");

    assert!(rendered.contains("FINDINGS · 1 TRIAGED · 1 PENDING"));
    assert!(rendered.contains("SQL injection in search"));
    assert!(rendered.contains("src/search.ts:12-14"));
}

#[test]
fn recent_module_activity_uses_recon_snapshot_when_present() {
    use crate::app::ReconSnapshot;
    use kuzushi_core::{ReconHost, ReconService};

    let mut app = ShellApp::new(V2Config::default(), None);
    app.recon_snapshot = Some(ReconSnapshot {
        hosts: vec![ReconHost {
            id: "h1".to_string(),
            workspace_id: "ws".to_string(),
            address: "192.0.2.10".to_string(),
            hostname: Some("acme-checkout.com".to_string()),
            state: "alive".to_string(),
        }],
        services: vec![ReconService {
            id: "s1".to_string(),
            host_id: "h1".to_string(),
            port: 443,
            proto: "tcp".to_string(),
            name: Some("https".to_string()),
            banner: Some("nginx/1.24 · TLS1.3".to_string()),
            state: "open".to_string(),
        }],
        notes: Vec::new(),
        last_tool: Some("recon:nmap".to_string()),
        last_target: Some("acme-checkout.com".to_string()),
    });

    let lines = recent_module_activity_lines(&app, "recon", 8);
    let rendered: String = lines
        .iter()
        .flat_map(|line| line.spans.iter().map(|sp| sp.content.as_ref()))
        .collect::<Vec<_>>()
        .join("");

    assert!(
        rendered.contains("acme-checkout.com"),
        "expected snapshot host in output, got:\n{rendered}"
    );
    assert!(
        rendered.contains("443"),
        "expected snapshot port 443 in output, got:\n{rendered}"
    );
    assert!(
        rendered.contains("nginx/1.24"),
        "expected snapshot banner in output, got:\n{rendered}"
    );
}

#[test]
fn recent_module_activity_falls_back_to_log_when_no_snapshot() {
    // No snapshot is populated → renderer must keep falling back to the
    // legacy `app.log` grep, which is the pre-snapshot behaviour.
    let mut app = ShellApp::new(V2Config::default(), None);
    // Inject a recon-shaped log line that would be picked up by
    // `recent_module_log` filter (prefix == "result", body contains "recon").
    app.log(
        "result",
        "recon:nmap discovered 1 host and 2 open services for 192.0.2.10",
    );

    let lines = recent_module_activity_lines(&app, "recon", 8);
    let rendered: String = lines
        .iter()
        .flat_map(|line| line.spans.iter().map(|sp| sp.content.as_ref()))
        .collect::<Vec<_>>()
        .join("");

    assert!(
        rendered.contains("recon:nmap discovered 1 host"),
        "expected fallback log-grep line in output, got:\n{rendered}"
    );
}

#[test]
fn sast_progress_bars_use_scan_progress_per_task_when_present() {
    use kuzushi_core::ScanProgress;
    use std::collections::BTreeMap;

    let mut app = ShellApp::new(V2Config::default(), None);
    app.focused_module = Some("sast".to_string());
    app.shell_view = ShellView::ModuleRun;
    app.scan = Some(crate::app::ScanPanelState {
        run_id: Some("run-real-progress".to_string()),
        target: std::path::PathBuf::from("./demo"),
        stage: "scanning".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    });

    let mut per_task = BTreeMap::new();
    per_task.insert("agentic-sast".to_string(), (87usize, 120usize));
    per_task.insert("semgrep".to_string(), (612usize, 612usize));
    app.scan_progress = Some(ScanProgress {
        total: 732,
        done: 699,
        current_tool: Some("semgrep".to_string()),
        current_target: Some("./demo".to_string()),
        per_task,
    });

    let area = Rect::new(0, 0, 120, 40);
    let lines = module_run_lines(&app, area);
    let rendered: String = lines
        .iter()
        .flat_map(|line| line.spans.iter().map(|sp| sp.content.as_ref()))
        .collect::<Vec<_>>()
        .join("");

    assert!(
        rendered.contains("612/612"),
        "expected real semgrep done count, got:\n{rendered}"
    );
    assert!(
        rendered.contains("87/120"),
        "expected real agentic-sast progress count, got:\n{rendered}"
    );
    assert!(
        rendered.contains("semgrep"),
        "expected semgrep label in progress bar, got:\n{rendered}"
    );
    assert!(
        rendered.contains("agentic-sast"),
        "expected agentic-sast label in progress bar, got:\n{rendered}"
    );
}

#[test]
fn threat_story_model_from_doc_sorts_by_impact_severity() {
    let doc = serde_json::json!({
        "threats": [
            {"id": "T-001", "title": "low risk",  "impact": "low",      "category": "spoofing",  "attackVector": "vec1"},
            {"id": "T-002", "title": "critical bug", "impact": "critical","category": "tampering","attackVector": "vec2",
             "affectedFiles": [{"filePath": "src/api.rs", "startLine": 42}]},
            {"id": "T-003", "title": "high issue", "impact": "high",     "category": "elevation_of_privilege"}
        ]
    });
    let model = threat_story_model_from_doc(&doc).expect("non-empty stories");
    assert_eq!(model.header, "ATTACKER STORIES · 3");
    assert_eq!(model.rows.len(), 3);
    assert_eq!(model.rows[0].cells[0], "T-002");
    assert_eq!(model.rows[0].cells[1], "CRITICAL");
    assert_eq!(model.rows[0].details[1].value, "src/api.rs:42");
    assert_eq!(model.rows[1].cells[0], "T-003");
    assert_eq!(model.rows[1].cells[1], "HIGH");
    assert_eq!(model.rows[2].cells[0], "T-001");
}

#[test]
fn threat_story_model_from_doc_caps_visible_rows() {
    let doc = serde_json::json!({
        "threats": [
            {"id": "T-001", "title": "one", "impact": "high"},
            {"id": "T-002", "title": "two", "impact": "high"},
            {"id": "T-003", "title": "three", "impact": "high"},
            {"id": "T-004", "title": "four", "impact": "high"},
            {"id": "T-005", "title": "five", "impact": "high"},
            {"id": "T-006", "title": "six", "impact": "high"},
            {"id": "T-007", "title": "seven", "impact": "high"},
            {"id": "T-008", "title": "eight", "impact": "high"},
            {"id": "T-009", "title": "nine", "impact": "high"}
        ]
    });
    let model = threat_story_model_from_doc(&doc).expect("non-empty stories");
    assert_eq!(model.header, "ATTACKER STORIES · 9");
    assert_eq!(model.rows.len(), 8);
    assert_eq!(model.rows[7].cells[0], "T-008");
}

#[test]
fn threat_scope_model_from_doc_groups_by_impact() {
    let doc = serde_json::json!({
        "threats": [
            {"title": "a", "impact": "critical"},
            {"title": "b", "impact": "high"},
            {"title": "c", "impact": "high"},
            {"title": "e", "impact": "high"},
            {"title": "f", "impact": "high"},
            {"title": "g", "impact": "high"},
            {"title": "d", "impact": "medium"}
        ]
    });
    let model = threat_scope_model_from_doc(&doc).expect("non-empty");
    let buckets = &model.buckets;
    assert_eq!(model.header, "SCOPE · 7 issues");
    assert_eq!(buckets.len(), 3);
    assert_eq!(buckets[0].header, "CRITICAL · 1");
    assert_eq!(buckets[0].item_count, 1);
    assert_eq!(buckets[1].header, "HIGH · 5");
    assert_eq!(buckets[1].item_count, 5);
    assert_eq!(buckets[1].visible_items.len(), 4);
    assert_eq!(buckets[1].overflow_label.as_deref(), Some("… 1 more"));
    assert_eq!(buckets[2].header, "MEDIUM · 1");
    assert_eq!(buckets[2].item_count, 1);
}

#[test]
fn threats_stories_view_renders_attacker_story_cards() {
    let backend = TestBackend::new(120, 36);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Threat(ThreatView::Stories);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("ATTACKER STORIES"));
    assert!(rendered.contains("T-001"));
    assert!(rendered.contains("CRITICAL"));
    assert!(rendered.contains("attack"));
    assert!(rendered.contains("loc"));
    // Old placeholder gone
    assert!(!rendered.contains("malicious input reaches a sink"));
}

#[test]
fn threats_scope_view_renders_criticality_buckets() {
    let backend = TestBackend::new(120, 40);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Threat(ThreatView::Scope);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(
        rendered.contains("SCOPE · 11 ISSUES"),
        "expected SCOPE · 11 ISSUES in: {rendered}"
    );
    assert!(rendered.contains("CRITICAL · 2"));
    assert!(rendered.contains("HIGH · 3"));
    assert!(rendered.contains("OUT OF SCOPE"));
    // Old placeholders gone
    assert!(!rendered.contains("auth, request parsing"));
}

#[test]
fn threat_stride_rollup_from_doc_parses_real_threats() {
    let doc = serde_json::json!({
        "threats": [
            {"id": "T-001", "category": "spoofing",          "title": "spoofed login",    "impact": "high"},
            {"id": "T-002", "category": "spoofing",          "title": "stolen token",     "impact": "medium"},
            {"id": "T-003", "category": "tampering",         "title": "config tamper",    "impact": "critical"},
            {"id": "T-004", "category": "information-disclosure", "title": "log leak",    "impact": "low"},
        ]
    });
    let rollup =
        threat_stride_rollup_from_doc(&doc).expect("expected rollup from non-empty threats");
    assert_eq!(rollup.header, "STRIDE ROLLUP · 4 issues");
    assert_eq!(rollup.rows.len(), 6);

    let spoof = &rollup.rows[0];
    assert_eq!(spoof.cells[0], "S");
    assert_eq!(spoof.cells[1], "Spoofing");
    assert_eq!(spoof.cells[2], "2");
    assert_eq!(spoof.cells[3], "issues");
    assert_eq!(spoof.tone, ThreatStrideTone::High);
    assert!(spoof.detail.as_deref().unwrap().contains("spoofed login"));
    assert!(spoof.detail.as_deref().unwrap().contains("stolen token"));

    let tamper = &rollup.rows[1];
    assert_eq!(tamper.cells[2], "1");
    assert_eq!(tamper.cells[3], "issue");
    assert_eq!(tamper.tone, ThreatStrideTone::Critical);
    assert_eq!(tamper.detail.as_deref(), Some("config tamper"));

    let repud = &rollup.rows[2];
    assert_eq!(repud.cells[2], "0");
    assert_eq!(repud.tone, ThreatStrideTone::Low);
    assert_eq!(repud.detail, None);

    let info = &rollup.rows[3];
    assert_eq!(info.cells[2], "1");
    assert_eq!(info.tone, ThreatStrideTone::Low);
    assert_eq!(info.detail.as_deref(), Some("log leak"));
}

#[test]
fn threat_stride_rollup_from_doc_returns_none_on_empty_or_missing_threats() {
    assert!(threat_stride_rollup_from_doc(&serde_json::json!({})).is_none());
    assert!(threat_stride_rollup_from_doc(&serde_json::json!({"threats": []})).is_none());
    assert!(threat_stride_rollup_from_doc(&serde_json::json!({"threats": null})).is_none());
}

#[test]
fn threat_stride_rollup_from_doc_normalizes_underscored_categories() {
    let doc = serde_json::json!({
        "threats": [
            {"category": "denial_of_service",        "title": "ddos",  "impact": "medium"},
            {"category": "elevation_of_privilege",   "title": "sudo bypass", "impact": "critical"},
        ]
    });
    let rollup = threat_stride_rollup_from_doc(&doc).expect("rollup should accept underscored");
    let dos = &rollup.rows[4];
    assert_eq!(dos.cells[0], "D");
    assert_eq!(dos.cells[2], "1");
    let elev = &rollup.rows[5];
    assert_eq!(elev.cells[0], "E");
    assert_eq!(elev.cells[2], "1");
    assert_eq!(elev.tone, ThreatStrideTone::Critical);
}

#[test]
fn threats_summary_view_is_review_first_without_fake_observations() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(tmp.path()).unwrap();
    kuzushi_core::save_persistent_threat_model(
        tmp.path(),
        &serde_json::json!({
            "version": "2.0",
            "summary": {"text": "checkout threat model"},
            "dfd": {
                "nodes": [
                    {"id": "actor-user", "type": "external-entity", "name": "User"},
                    {"id": "web", "type": "process", "name": "Web"},
                    {"id": "db", "type": "data-store", "name": "DB"}
                ],
                "flows": [{"id": "flow-1", "sourceId": "actor-user", "targetId": "web"}],
                "trustBoundaries": [{"id": "tb-1", "name": "edge"}]
            },
            "threats": [{"id": "T-1", "category": "spoofing", "title": "stolen token"}],
            "assumptions": ["session cookies are in scope"],
            "missingInputs": ["production network diagram"]
        }),
        true,
    )
    .unwrap();
    let backend = TestBackend::new(132, 36);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.shell_view = ShellView::Threat(ThreatView::Summary);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("THREAT MODEL REVIEW"));
    assert!(rendered.contains("checkout threat model"));
    assert!(rendered.contains("assets             3"));
    assert!(rendered.contains("actors             1"));
    assert!(rendered.contains("data flows         1"));
    assert!(rendered.contains("trust boundaries   1"));
    assert!(rendered.contains("session cookies are in scope"));
    assert!(rendered.contains("production network diagram"));
    assert!(rendered.contains("none pending"));
    assert!(rendered.contains("not exploit proof"));
    assert!(rendered.contains(".kuzushi/threat-model.json"));
    assert!(!rendered.contains("admin.acme-checkout.com"));
    assert!(!rendered.contains("shares the jwt secret"));
}

#[test]
fn threats_editor_names_persistent_artifact_path() {
    let backend = TestBackend::new(120, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::ThreatEditor;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("THREAT MODEL EDIT"));
    assert!(rendered.contains(".kuzushi/threat-model.json"));
}

#[test]
fn threats_summary_unknown_state_does_not_invent_data() {
    let backend = TestBackend::new(120, 32);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Threat(ThreatView::Summary);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("THREAT MODEL REVIEW"));
    assert!(rendered.contains("build or import a threat model to populate this view"));
    assert!(rendered.contains("assets"));
    assert!(rendered.contains("no threat model artifact"));
    assert!(!rendered.contains("admin.acme-checkout.com"));
}

#[test]
fn threats_stride_view_renders_design_rollup() {
    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Threat(ThreatView::Stride);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(
        rendered.contains("STRIDE ROLLUP"),
        "expected STRIDE ROLLUP header in: {rendered}"
    );
    assert!(rendered.contains("Spoofing"));
    assert!(rendered.contains("Tampering"));
    assert!(rendered.contains("Repudiation"));
    assert!(rendered.contains("Info-disclosure"));
    assert!(rendered.contains("DoS"));
    assert!(rendered.contains("Elev-of-priv"));
    // Old hardcoded content must be gone.
    assert!(!rendered.contains("entrypoints"));
    assert!(!rendered.contains("scanners"));
}

#[test]
fn deferred_recon_module_is_not_focusable_from_catalog() {
    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Catalog;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();

    assert!(!app
        .registry
        .modules()
        .any(|module| module.metadata().id == "recon"));
    assert!(app.registry.resolve_tool("recon:nmap").is_some());
}

#[test]
fn focused_offense_review_module_renders_recent_threat_hunt_activity() {
    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.log.clear();
    app.log("offense-review", "actor 1/4 dispatched");
    app.log("offense-review", "actor 2/4 found path-traversal sink");
    app.handle_command(crate::commands::ShellCommand::Use(
        "offense-review".to_string(),
    ));

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(
        rendered.contains("RECENT THREAT-HUNT ACTIVITY"),
        "expected design section header for offense-review: {rendered}"
    );
    assert!(rendered.contains("actor 1/4 dispatched"));
}

#[test]
fn module_run_transcript_uses_growing_console_glyphs() {
    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.log.clear();
    app.log(">", "/scan");
    app.log("scan", "starting ./demo");
    app.log("finding", "abc123 high dangerous sink");
    app.log("error", "scanner failed");
    app.scan = Some(crate::app::ScanPanelState {
        run_id: Some("run-123456".to_string()),
        target: std::path::PathBuf::from("./demo"),
        stage: "agentic-sast tracing".to_string(),
        findings_count: 1,
        running: true,
        abort_requested: false,
        error: None,
    });
    app.shell_view = ShellView::ModuleRun;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("SCAN PROGRESS"));
    // Spinner cycles through SPINNER_FRAMES based on `app.spinner_phase`; any frame is valid.
    assert!(
        SPINNER_FRAMES.iter().any(|frame| rendered.contains(frame)),
        "expected one of the braille spinner frames in: {rendered}"
    );
    assert!(rendered.contains("● /scan"));
    assert!(rendered.contains("⏵ scan starting ./demo"));
    assert!(rendered.contains("▸ finding abc123 high dangerous sink"));
    assert!(rendered.contains("✗ error scanner failed"));
}

#[test]
fn direct_tool_run_header_does_not_show_pending_scan_run() {
    let backend = TestBackend::new(96, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.focused_module = Some("context".to_string());
    app.shell_view = ShellView::ModuleRun;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("tool run"));
    assert!(rendered.contains("CONTEXT BUILD"));
    assert!(rendered.contains(".kuzushi/context-snapshot.json"));
    assert!(!rendered.contains("SCAN PROGRESS"));
    assert!(!rendered.contains("run pending"));
}

#[test]
fn active_tool_run_uses_live_tool_chrome_not_scan_chrome() {
    let backend = TestBackend::new(96, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.focused_module = Some("recon".to_string());
    app.set_running_tool_for_test("recon:nmap");
    app.shell_view = ShellView::ModuleRun;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("TOOL RUN"));
    assert!(rendered.contains("recon:nmap"));
    assert!(
        SPINNER_FRAMES.iter().any(|frame| rendered.contains(frame)),
        "expected active spinner frame in: {rendered}"
    );
    assert!(!rendered.contains("SCAN PROGRESS"));
    assert!(!rendered.contains("no scan in flight"));
}

#[test]
fn renders_options_table_readably_at_80_columns() {
    let backend = TestBackend::new(80, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.option_store.set_value(
        OptionScope::Session,
        OptionTarget::Tool("sast:scan".to_string()),
        "triage",
        serde_json::json!(true),
    );
    app.shell_view = ShellView::Options(crate::app::OptionsView {
        tool_name: "sast:scan".to_string(),
        filter: crate::app::OptionsFilter::Standard,
    });

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("OPTIONS"));
    assert!(rendered.contains("sast:scan"));
    assert!(rendered.contains("tasks"));
    assert!(rendered.contains("disabledTasks"));
    assert!(rendered.contains("triage"));
    assert!(rendered.contains("true"));
    assert!(rendered.contains("set <key> <value>"));
    assert!(!rendered.contains("┌"));
}

#[test]
fn renders_sast_task_picker_readably_at_80_columns() {
    let backend = TestBackend::new(80, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::SastTasks;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("SAST TASKS"));
    assert!(rendered.contains("semgrep"));
    assert!(rendered.contains("codeql"));
    assert!(rendered.contains("auto + denylist"));
    assert!(!rendered.contains("┌"));
}

#[test]
fn renders_kb_attachments_readably_at_80_columns() {
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.kb_view.module_id = "x-ray".to_string();
    app.kb_view.artifacts = vec![kuzushi_core::KnownArtifact {
        module_id: "x-ray".to_string(),
        path: "x-ray/x-ray.md".to_string(),
        description: "x-ray report".to_string(),
        exists: true,
    }];
    app.kb_view.attachments = vec![kuzushi_core::AttachmentRecord {
        id: "A-123456789abc".to_string(),
        module_id: "x-ray".to_string(),
        kind: kuzushi_core::AttachmentKind::Url,
        source: "https://example.test/design".to_string(),
        title: "example.test".to_string(),
        metadata_only: true,
        content_hash: None,
        byte_count: None,
        status: "metadata-only; URL was not fetched".to_string(),
        updated_at_unix: 1,
    }];
    app.shell_view = ShellView::KnowledgeBase;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("KB ATTACHMENTS"));
    assert!(rendered.contains("x-ray/x-ray.md"));
    assert!(rendered.contains("A-123456789abc"));
    assert!(rendered.contains("metadata-only"));
    assert!(!rendered.contains("┌"));
}

#[test]
fn renders_context_status_readably_at_80_columns() {
    let backend = TestBackend::new(80, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.context_view = crate::app::ContextSnapshotView {
        snapshot_path: Some(context_snapshot_fixture_path()),
        exists: true,
        status: "snapshot present; 2 indexed file(s). Next: context regen repo".to_string(),
        target: Some("/tmp/demo".to_string()),
        discovery: Some("auto".to_string()),
        files_indexed: Some(2),
        total_files: Some(2),
        languages: vec!["Rust".to_string()],
        frameworks: vec!["Cargo".to_string()],
        generated_slices: vec!["repo".to_string(), "app-model".to_string()],
        stale_slices: Vec::new(),
    };
    app.shell_view = ShellView::Context;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("CONTEXT"));
    assert!(rendered.contains("context-snapshot.json"));
    assert!(rendered.contains("Rust"));
    assert!(rendered.contains("context regen repo"));
    assert!(!rendered.contains("┌"));
}

#[test]
fn active_context_build_view_shows_live_feedback() {
    let backend = TestBackend::new(96, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.focused_module = Some("context".to_string());
    app.shell_view = ShellView::Context;
    app.set_running_tool_for_test("context:build");

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("mode:run"));
    assert!(rendered.contains("context:build"));
    assert!(rendered.contains("indexing repository context"));
    assert!(rendered.contains("request abort"));
    assert!(rendered.contains("kuzushi/context/run>"));
    assert!(!rendered.contains("SCAN PROGRESS"));
}

#[test]
fn context_build_view_surfaces_malformed_snapshot() {
    let backend = TestBackend::new(96, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.focused_module = Some("context".to_string());
    app.shell_view = ShellView::Context;
    app.context_view.snapshot_path = Some(context_snapshot_fixture_path());
    app.context_view.status = "malformed context snapshot. Next: context build".to_string();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("malformed context snapshot"));
    assert!(rendered.contains("context-snapshot.json"));
    assert!(!rendered.contains("no snapshot yet"));
}

#[test]
fn renders_workspace_status_readably_at_80_columns() {
    let backend = TestBackend::new(80, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.workspace_view = crate::app::WorkspaceView {
        root: Some(std::path::PathBuf::from("/tmp/kuzushi-demo")),
        state_dir: Some(std::path::PathBuf::from("/tmp/kuzushi-demo/.kuzushi/v2")),
        findings_db: Some(std::path::PathBuf::from(
            "/tmp/kuzushi-demo/.kuzushi/v2/findings.sqlite3",
        )),
        findings_count: Some(2),
        last_export: Some(std::path::PathBuf::from("/tmp/findings.json")),
        status: "workspace ready; 2 finding(s). Next: workspace scope init or workspace export findings <path> [format]"
            .to_string(),
    };
    app.shell_view = ShellView::Workspace;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("WORKSPACE"));
    assert!(rendered.contains("findings.sqlite3"));
    assert!(rendered.contains("findings.json"));
    assert!(rendered.contains("workspace export"));
    assert!(!rendered.contains("┌"));
}

#[test]
fn workspace_view_renders_findings_rollup_bar_when_findings_exist() {
    // Mockup parity: `design/mockups/workspace.jsx::rollupBar`. With
    // persisted findings, the workspace view shows a 28-cell severity
    // rollup bar per category so the operator sees the distribution
    // shape at a glance.
    let backend = TestBackend::new(120, 36);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.workspace_view = crate::app::WorkspaceView {
        root: Some(std::path::PathBuf::from("/tmp/kuzushi-demo")),
        state_dir: None,
        findings_db: None,
        findings_count: Some(38),
        last_export: None,
        status: "workspace ready".to_string(),
    };
    app.findings = (0..38)
        .map(|index| {
            let sev = match index % 4 {
                0 => Severity::Critical,
                1 => Severity::High,
                2 => Severity::Medium,
                _ => Severity::Low,
            };
            Finding::new_semgrep(
                format!("rule.{index}"),
                "src/x.rs",
                index + 1,
                None,
                sev,
                "demo",
            )
        })
        .collect();
    app.shell_view = ShellView::Workspace;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(
        rendered.contains("FINDINGS ROLLUP"),
        "missing rollup divider: {rendered}"
    );
    assert!(rendered.contains("CRITICAL"));
    assert!(rendered.contains("HIGH"));
    assert!(rendered.contains("MEDIUM"));
    assert!(rendered.contains("LOW"));
    assert!(rendered.contains("█"));
    assert!(rendered.contains("░"));
    assert!(rendered.contains("/38"));
}

#[test]
fn workspace_view_skips_rollup_when_no_findings() {
    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Workspace;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    // No findings → no FINDINGS ROLLUP section (no empty bars to show).
    assert!(!rendered.contains("FINDINGS ROLLUP"));
}

#[test]
fn plain_options_table_has_no_ansi_or_box_drawing() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.option_store.set_value(
        OptionScope::Session,
        OptionTarget::Tool("sast:scan".to_string()),
        "triage",
        serde_json::json!(true),
    );
    app.shell_view = ShellView::Options(crate::app::OptionsView {
        tool_name: "sast:scan".to_string(),
        filter: crate::app::OptionsFilter::Standard,
    });

    let rendered = render_plain_app(&app, 80);

    assert!(rendered.contains("OPTIONS"));
    assert!(rendered.contains("sast:scan"));
    assert!(rendered.contains("triage"));
    assert!(rendered.contains("true"));
    assert!(rendered.contains("Next: set <key> <value>"));
    assert_strict_plain_80(&rendered);
}

#[test]
fn plain_kb_list_has_no_ansi_or_box_drawing() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.kb_view.module_id = "x-ray".to_string();
    app.kb_view.artifacts = vec![kuzushi_core::KnownArtifact {
        module_id: "x-ray".to_string(),
        path: "x-ray/x-ray.md".to_string(),
        description: "x-ray report".to_string(),
        exists: true,
    }];
    app.kb_view.attachments = vec![kuzushi_core::AttachmentRecord {
        id: "A-123456789abc".to_string(),
        module_id: "x-ray".to_string(),
        kind: kuzushi_core::AttachmentKind::Url,
        source: "https://example.test/design".to_string(),
        title: "example.test".to_string(),
        metadata_only: true,
        content_hash: None,
        byte_count: None,
        status: "metadata-only; URL was not fetched".to_string(),
        updated_at_unix: 1,
    }];
    app.shell_view = ShellView::KnowledgeBase;

    let rendered = render_plain_app(&app, 80);

    assert!(rendered.contains("KB ATTACHMENTS"));
    assert!(rendered.contains("x-ray/x-ray.md"));
    assert!(rendered.contains("A-123456789abc"));
    assert!(rendered.contains("metadata-only"));
    assert!(rendered.contains("Next: kb [module]"));
    assert_strict_plain_80(&rendered);
}

#[test]
fn plain_context_status_has_no_ansi_or_box_drawing() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.context_view = crate::app::ContextSnapshotView {
        snapshot_path: Some(context_snapshot_fixture_path()),
        exists: true,
        status: "snapshot present; 2 indexed file(s). Next: context regen repo".to_string(),
        target: Some("/tmp/demo".to_string()),
        discovery: Some("auto".to_string()),
        files_indexed: Some(2),
        total_files: Some(2),
        languages: vec!["Rust".to_string()],
        frameworks: vec!["Cargo".to_string()],
        generated_slices: vec!["repo".to_string(), "app-model".to_string()],
        stale_slices: Vec::new(),
    };
    app.shell_view = ShellView::Context;

    let rendered = render_plain_app(&app, 80);

    assert!(rendered.contains("CONTEXT"));
    assert!(rendered.contains("context-snapshot.json"));
    assert!(rendered.contains("Rust"));
    assert!(rendered.contains("context regen repo"));
    assert_strict_plain_80(&rendered);
}

#[test]
fn plain_context_guidance_wraps_without_truncating_next_steps() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Context;

    let rendered = render_plain_app(&app, 56);

    assert!(rendered.contains("No context snapshot exists yet."));
    assert!(rendered.contains(".kuzushi/context-snapshot.json"));
    assert!(rendered.contains("context build"));
    assert!(rendered.contains("context regen repo"));
    assert!(!rendered.contains("context-s..."));
    assert_strict_plain_width(&rendered, 56);
}

#[test]
fn plain_workspace_guidance_wraps_without_truncating_export_command() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.workspace_view = crate::app::WorkspaceView {
        root: Some(std::path::PathBuf::from("/tmp/kuzushi-demo")),
        state_dir: Some(std::path::PathBuf::from("/tmp/kuzushi-demo/.kuzushi/v2")),
        findings_db: Some(std::path::PathBuf::from(
            "/tmp/kuzushi-demo/.kuzushi/v2/findings.sqlite3",
        )),
        findings_count: Some(2),
        last_export: None,
        status: "workspace ready; 2 finding(s). Next: workspace scope init or workspace export findings <path> [format]"
            .to_string(),
    };
    app.shell_view = ShellView::Workspace;

    let rendered = render_plain_app(&app, 52);

    assert!(rendered.contains("workspace ready; 2 finding(s)."));
    assert!(rendered.contains("workspace scope init"));
    assert!(rendered.contains("workspace export findings <path> [format]"));
    assert!(!rendered.contains("workspace export findings..."));
    assert_strict_plain_width(&rendered, 52);
}

#[test]
fn plain_help_guidance_wraps_without_truncating_command_shapes() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Help;

    let rendered = render_plain_app(&app, 64);

    assert!(rendered.contains("HELP"));
    assert!(rendered.contains("ask <question>"));
    assert!(rendered.contains("enter agent mode"));
    assert!(rendered.contains("workspace export findings <path>"));
    assert!(rendered.contains("/workspace export findings <path>"));
    assert!(!rendered.contains("workspace export findings <..."));
    assert_strict_plain_width(&rendered, 64);
}

#[test]
fn renders_config_onboarding_without_silent_model_selection() {
    let backend = TestBackend::new(100, 28);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.config.model = None;
    app.session_thinking_level = None;
    app.selected_model_index = 2;
    app.shell_view = ShellView::Config;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("provider"));
    assert!(rendered.contains("unconfigured"));
    assert!(rendered.contains("reasoning"));
    assert!(rendered.contains("default"));
    assert!(rendered.contains("onboarding"));
    assert!(rendered.contains("Up/Down"));
    assert!(rendered.contains(">"));
    // The primary OpenAI slot is auth-aware (API-key model without stored
    // OAuth credentials, OAuth model with them); both are explicit selectors.
    assert!(rendered.contains("openai:gpt-5.5") || rendered.contains("openai-oauth:gpt-5.4"));
    assert!(rendered.contains("anthropic:claude-sonnet-4-6"));
    assert!(!rendered.contains("┌"));
}

#[test]
fn plain_config_onboarding_uses_explicit_model_selection() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.config.model = None;
    app.session_thinking_level = None;
    app.shell_view = ShellView::Config;

    let rendered = render_plain_app(&app, 80);

    assert!(rendered.contains("CONFIG"));
    assert!(rendered.contains("model: unconfigured"));
    assert!(rendered.contains("onboarding: model <n> selects an explicit provider:model"));
    // The primary OpenAI slot is auth-aware; either form is an explicit selector.
    assert!(rendered.contains("openai:gpt-5.5") || rendered.contains("openai-oauth:gpt-5.4"));
    assert!(rendered.contains("anthropic:claude-sonnet-4-6"));
    assert_strict_plain_80(&rendered);
}

#[test]
fn renders_help_grouped_by_operator_workflow() {
    let backend = TestBackend::new(110, 130);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Help;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    for heading in [
        "NAVIGATION",
        "RUN / SCAN",
        "OPTIONS / TASKS",
        "CONTEXT / KB",
        "FINDINGS / EVIDENCE",
        "AUTH / CONFIG / MODEL",
        "SESSION",
    ] {
        assert!(rendered.contains(heading), "missing help group {heading}");
    }
    assert!(rendered.contains("options [tool]"));
    assert!(rendered.contains("task toggle"));
    assert!(rendered.contains("kb [module]"));
    assert!(rendered.contains("auth login"));
    assert!(rendered.contains("? opens help"));
    assert!(rendered.contains("?text"));
    assert!(rendered.contains("/ask <question>"));
    assert!(rendered.contains("ask <question>"));
    assert!(!rendered.contains("┌"));
}

#[test]
fn renders_help_aliases_and_examples_from_command_specs() {
    let backend = TestBackend::new(120, 130);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Help;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    for example in shell_help_examples() {
        assert!(
            rendered.contains(example),
            "missing featured help example {example}"
        );
    }

    for (category, alias) in [
        (ShellCommandCategory::Navigation, "/h"),
        (ShellCommandCategory::RunScan, "run ."),
        (ShellCommandCategory::OptionsTasks, "task deny <id>"),
        (ShellCommandCategory::ContextKb, "attachments"),
        (ShellCommandCategory::FindingsEvidence, "open F-0001"),
        (ShellCommandCategory::AuthConfigModel, "model 1"),
        (ShellCommandCategory::Session, "q"),
    ] {
        assert!(
            shell_command_specs()
                .any(|spec| spec.category == category && spec.aliases.contains(&alias)),
            "sample alias {alias:?} is not registered for {category:?}"
        );
        assert!(
            rendered.contains(alias),
            "missing help alias sample {alias:?} for {category:?}"
        );
    }

    // Per `design/mockups/help.jsx`, sections embed their blurb on the
    // category divider rule line — no separate `aliases / examples` table
    // header.  The featured-example + per-category alias assertions
    // above already prove the alias/example text reaches the buffer.
    assert!(rendered.contains("browse modules and tools"));
    assert!(!rendered.contains("TypeScript"));
    assert!(!rendered.contains("Ink"));
}

#[test]
fn plain_help_aliases_and_examples_are_width_safe() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Help;

    let rendered = render_plain_app(&app, 80);

    assert!(rendered.contains("HELP"));
    assert!(rendered.contains("browse modules and tools"));
    for example in shell_help_examples() {
        assert!(
            rendered.contains(example),
            "missing plain help example {example}"
        );
    }
    for alias in [
        "/h",
        "run .",
        "task deny <id>",
        "attachments",
        "open F-0001",
        "model 1",
        "q",
    ] {
        assert!(rendered.contains(alias), "missing plain help alias {alias}");
    }
    assert!(!rendered.contains("TypeScript"));
    assert!(!rendered.contains("Ink"));
    assert_strict_plain_80(&rendered);
}

#[test]
fn viewport_help_remains_navigable_at_24_rows() {
    let backend = TestBackend::new(110, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Help;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let first_page = format!("{:?}", terminal.backend().buffer());
    assert!(first_page.contains("HELP"));
    assert!(first_page.contains("NAVIGATION"));

    app.help_scroll = usize::MAX;
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let last_page = format!("{:?}", terminal.backend().buffer());
    assert!(last_page.contains("quit"), "{last_page}");
    assert!(last_page.contains("PgUp/PgDn scroll"), "{last_page}");
    assert!(!last_page.contains("┌"));
}

#[test]
fn viewport_tools_remain_navigable_at_24_rows() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let last_tool = app.registry.tools().last().unwrap().name.clone();
    app.shell_view = ShellView::Tools;
    app.tools_scroll = usize::MAX;

    let backend = TestBackend::new(110, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(
        rendered.contains(&last_tool),
        "missing last tool {last_tool}"
    );
    assert!(rendered.contains("PgUp/PgDn scroll"));
    assert!(!rendered.contains("┌"));
}

#[test]
fn viewport_expanded_modules_remain_navigable_at_24_rows() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let last_defense_module = crate::ui_view_models::catalog_model(&app)
        .groups
        .iter()
        .find(|group| group.category == "DEFENSE")
        .unwrap()
        .rows
        .last()
        .unwrap()
        .id
        .clone();
    app.shell_view = ShellView::Catalog;
    app.catalog_expanded = true;
    app.modules_scroll = usize::MAX;

    let backend = TestBackend::new(110, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(
        rendered.contains(&last_defense_module),
        "missing last module {last_defense_module}"
    );
    assert!(rendered.contains("PgUp/PgDn scroll"));
    assert!(!rendered.contains("┌"));
}

#[test]
fn workbench_findings_pane_windows_cursor_into_view() {
    let backend = TestBackend::new(100, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Workbench;
    app.workbench_focus = WorkbenchPane::Findings;
    app.findings_cursor = 29;
    app.findings = (0..30)
        .map(|index| {
            let mut finding = Finding::new_semgrep(
                format!("demo.rule.{index:04}"),
                "src/app.rs",
                index + 1,
                None,
                Severity::High,
                format!("title-{index:02}\nEvidence: proof-{index:02}"),
            );
            finding.fingerprint = format!("fp-{index:04}");
            finding
        })
        .collect();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    // The FINDINGS pane windows around the cursor: the last alias is visible,
    // the first has scrolled off.
    assert!(rendered.contains("F-0030"));
    assert!(!rendered.contains("F-0001"));
}

#[test]
fn keybind_footer_advertises_workbench_navigation_keys_at_80_columns() {
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Workbench;
    app.findings = vec![Finding::new_semgrep(
        "demo.rule",
        "src/app.rs",
        1,
        None,
        Severity::High,
        "title\nEvidence: proof",
    )];

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("Tab"), "{rendered}");
    assert!(rendered.contains("j/k"), "{rendered}");
    assert!(rendered.contains("Enter"), "{rendered}");
}

#[test]
fn keybind_footer_advertises_module_run_actor_and_pause_resume_keys() {
    let backend = TestBackend::new(100, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    let cancel = ScanCancellation::default();
    app.set_scan_cancel_for_test(cancel.clone());
    app.scan = Some(crate::app::ScanPanelState {
        run_id: Some("run-1".to_string()),
        target: std::path::PathBuf::from("."),
        stage: "running".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    });
    app.shell_view = ShellView::ModuleRun;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let running = format!("{:?}", terminal.backend().buffer());
    assert!(running.contains("1..4 actor"));
    assert!(running.contains("p pause"));
    assert!(!running.contains("[actor 1]"));

    cancel.pause();
    if let Some(scan) = &mut app.scan {
        scan.stage = "paused".to_string();
    }
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let paused = format!("{:?}", terminal.backend().buffer());
    assert!(paused.contains("1..4 actor"));
    assert!(paused.contains("r resume"));
    // The unbracketed pause hint is gone too (sanity: keybind list flips
    // pause→resume on pause).
    assert!(!paused.contains("p pause"));
}

#[test]
fn renders_agent_chat_mode_while_question_is_active() {
    let backend = TestBackend::new(80, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(
        V2Config {
            model: Some("openai:gpt-4.1".to_string()),
            ..V2Config::default()
        },
        None,
    );
    app.agent_chat = Some(crate::app::AgentChatView {
        question: "What should I run first?".to_string(),
        answer: None,
        running: true,
        abort_requested: false,
        error: None,
        history: Vec::new(),
        run_id: None,
        started_secs: 0,
        failure_context: None,
        pending_failure_context: None,
    });
    app.shell_view = ShellView::AgentChat;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("AGENT"));
    assert!(rendered.contains("running"));
    assert!(rendered.contains("mode:agent"));
    assert!(rendered.contains("agent: active"));
    assert!(rendered.contains("kuzushi/agent>"));
    assert!(!rendered.contains("┌"));
}

#[test]
fn renders_honest_abort_requested_states() {
    let backend = TestBackend::new(96, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(
        V2Config {
            model: Some("openai:gpt-4.1".to_string()),
            ..V2Config::default()
        },
        None,
    );
    app.shell_view = ShellView::AgentChat;
    app.agent_chat = Some(crate::app::AgentChatView {
        question: "What changed?".to_string(),
        answer: None,
        running: true,
        abort_requested: true,
        error: None,
        history: Vec::new(),
        run_id: None,
        started_secs: 0,
        failure_context: None,
        pending_failure_context: None,
    });

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let agent_rendered = format!("{:?}", terminal.backend().buffer());
    assert!(agent_rendered.contains("abort requested"));
    assert!(agent_rendered.contains("Process kill is not confirmed"));
    assert!(!agent_rendered.contains("killed"));

    let backend = TestBackend::new(96, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    app.shell_view = ShellView::ModuleRun;
    app.agent_chat = None;
    app.scan = Some(crate::app::ScanPanelState {
        run_id: Some("run-1".to_string()),
        target: std::path::PathBuf::from("."),
        stage: "abort requested".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: true,
        error: None,
    });

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let scan_rendered = format!("{:?}", terminal.backend().buffer());
    assert!(scan_rendered.contains("abort requested"));
    assert!(scan_rendered.contains("waiting for subprocess"));
    assert!(!scan_rendered.contains("killed"));
}

#[test]
fn agent_chat_renders_failure_handoff_panel() {
    let backend = TestBackend::new(120, 34);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.agent_chat = Some(crate::app::AgentChatView {
        question: "what next?".to_string(),
        answer: None,
        running: false,
        abort_requested: false,
        error: None,
        history: Vec::new(),
        run_id: None,
        started_secs: 0,
        failure_context: Some(kuzushi_core::run_artifacts::FailureToLlmContext {
            failed_stage: "semgrep:scan".to_string(),
            cause: "semgrep binary missing".to_string(),
            what_failed: "semgrep:scan did not complete successfully".to_string(),
            artifacts_available: vec![kuzushi_core::run_artifacts::RunArtifact {
                label: "run".to_string(),
                path: ui_run_artifact_relative_path("r-1", "run.json"),
                kind: "json".to_string(),
            }],
            missing_artifacts: vec!["findings.json".to_string()],
            allowed_proof_level: "artifact-review-only; runtime verification did not run"
                .to_string(),
            next_files_or_artifacts_to_inspect: vec![ui_run_artifact_relative_path(
                "r-1", "run.json",
            )],
            recovery_options: vec!["Install semgrep and rerun semgrep:scan.".to_string()],
            fallback_prompt: "Continue the failed Kuzushi run for semgrep:scan.".to_string(),
            claims_forbidden: vec!["validated".to_string(), "verified".to_string()],
        }),
        pending_failure_context: None,
    });
    app.shell_view = ShellView::AgentChat;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("FAILURE HANDOFF"));
    assert!(rendered.contains("semgrep:scan"));
    assert!(rendered.contains("artifact-review-only"));
    assert!(rendered.contains("findings.json"));
    assert!(rendered.contains("validated, verified"));
}

#[test]
fn failure_handoff_view_renders_current_context() {
    let backend = TestBackend::new(120, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.agent_chat = Some(crate::app::AgentChatView {
        question: String::new(),
        answer: None,
        running: false,
        abort_requested: false,
        error: None,
        history: Vec::new(),
        run_id: None,
        started_secs: 0,
        failure_context: Some(kuzushi_core::run_artifacts::FailureToLlmContext {
            failed_stage: "semgrep:scan".to_string(),
            cause: "semgrep binary missing".to_string(),
            what_failed: "semgrep:scan did not complete successfully".to_string(),
            artifacts_available: Vec::new(),
            missing_artifacts: vec!["findings.json".to_string()],
            allowed_proof_level: "artifact-review-only; runtime verification did not run"
                .to_string(),
            next_files_or_artifacts_to_inspect: vec!["failures.json".to_string()],
            recovery_options: vec!["Install semgrep.".to_string()],
            fallback_prompt: "Continue the failed Kuzushi run.".to_string(),
            claims_forbidden: vec!["verified".to_string()],
        }),
        pending_failure_context: None,
    });
    app.shell_view = ShellView::FailureHandoff;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("FAILURE HANDOFF"));
    assert!(rendered.contains("semgrep:scan"));
    assert!(rendered.contains("findings.json"));
    assert!(rendered.contains("Continue the failed Kuzushi run."));
}

#[test]
fn failure_handoff_view_reads_latest_failures_artifact() {
    let tmp = tempfile::tempdir().unwrap();
    let run_dir = ui_run_dir(Some(tmp.path()), "run-1");
    std::fs::create_dir_all(&run_dir).unwrap();
    std::fs::write(ui_latest_run_path(Some(tmp.path())), "run-1\n").unwrap();
    std::fs::write(
        run_dir.join("failures.json"),
        serde_json::json!({
            "runId": "run-1",
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

    let backend = TestBackend::new(120, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(tmp.path().to_path_buf());
    app.shell_view = ShellView::FailureHandoff;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("FAILURE HANDOFF"));
    assert!(rendered.contains("semgrep:scan"));
    assert!(rendered.contains("findings.json"));
    assert!(rendered.contains("Continue the failed Kuzushi run."));
}

#[test]
fn recommend_view_renders_latest_recommendations_artifact() {
    let tmp = tempfile::tempdir().unwrap();
    let run_dir = ui_run_dir(Some(tmp.path()), "run-1");
    std::fs::create_dir_all(&run_dir).unwrap();
    std::fs::write(ui_latest_run_path(Some(tmp.path())), "run-1\n").unwrap();
    std::fs::write(
        run_dir.join("recommendations.json"),
        serde_json::json!([
            {
                "tool": "semgrep:scan",
                "priority": "high",
                "reason": "Source files match the fast native SAST path.",
                "signals": ["frameworks: Falcon, Litestar, Sanic"],
                "requiresRuntime": false
            }
        ])
        .to_string(),
    )
    .unwrap();
    std::fs::write(
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

    let backend = TestBackend::new(120, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(tmp.path().to_path_buf());
    app.shell_view = ShellView::Recommend;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("RECOMMEND"));
    assert!(rendered.contains("semgrep:scan"));
    assert!(rendered.contains("surface risk"));
    assert!(rendered.contains("1 high/critical"));
    assert!(rendered.contains("critical=1"));
    assert!(rendered.contains("frameworks Next.js=1, Spring=1"));
    assert!(rendered.contains("frameworks: Falcon"));
    assert!(rendered.contains("⚠ high"));
    assert!(rendered.contains("Source files match"));
}

#[test]
fn renders_shell_module_plan_and_run_routing_modes() {
    let cases = [
        {
            let app = ShellApp::new(V2Config::default(), None);
            (app, "mode:shell", "kuzushi>")
        },
        {
            let mut app = ShellApp::new(V2Config::default(), None);
            app.focused_module = Some("sast".to_string());
            app.shell_view = ShellView::Module;
            (app, "mode:module", "kuzushi/sast>")
        },
        {
            let mut app = ShellApp::new(V2Config::default(), None);
            app.set_pending_plan(crate::app::PlanProposal {
                goal: "tighten SAST options".to_string(),
                summary: "set scanner controls".to_string(),
                changes: Vec::new(),
                unsupported: Vec::new(),
            });
            (app, "mode:plan", "kuzushi/plan>")
        },
        {
            let mut app = ShellApp::new(V2Config::default(), None);
            app.scan = Some(crate::app::ScanPanelState {
                run_id: Some("run-1".to_string()),
                target: std::path::PathBuf::from("."),
                stage: "running semgrep".to_string(),
                findings_count: 0,
                running: true,
                abort_requested: false,
                error: None,
            });
            app.shell_view = ShellView::ModuleRun;
            (app, "mode:run", "kuzushi/run>")
        },
        {
            let mut app = ShellApp::new(V2Config::default(), None);
            app.focused_module = Some("context".to_string());
            app.shell_view = ShellView::ModuleRun;
            (app, "mode:module", "kuzushi/context>")
        },
        {
            let mut app = ShellApp::new(V2Config::default(), None);
            app.focused_module = Some("context".to_string());
            app.set_running_tool_for_test("context:build");
            app.shell_view = ShellView::ModuleRun;
            (app, "mode:run", "kuzushi/context/run>")
        },
    ];

    for (app, mode, prompt) in cases {
        let backend = TestBackend::new(96, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains(mode), "missing {mode} in {rendered}");
        assert!(
            rendered.contains("KUZUSHI mode:"),
            "missing cockpit strip in {rendered}"
        );
        assert!(
            rendered.contains(" · target:"),
            "missing target separator in {rendered}"
        );
        assert!(
            rendered.contains(" · ctx:"),
            "missing ctx separator in {rendered}"
        );
        assert!(
            rendered.contains(" · model:"),
            "missing model separator in {rendered}"
        );
        assert!(
            !rendered.contains("KUZUSHI  mode "),
            "old cockpit strip remained in {rendered}"
        );
        assert!(rendered.contains(prompt), "missing {prompt} in {rendered}");
        assert!(!rendered.contains("┌"));
    }
}

#[test]
fn renders_all_ink_parity_shell_surfaces() {
    let cases = vec![
        (ShellView::Home, "HOME"),
        (ShellView::Catalog, "MODULES"),
        (ShellView::Recommend, "RECOMMEND"),
        (ShellView::Module, "MODULE DETAIL"),
        (ShellView::ModuleRun, "TRANSCRIPT"),
        (ShellView::Workbench, "FINDINGS"),
        (ShellView::Tune, "TUNE"),
        (ShellView::Threat(ThreatView::Stories), "STORIES"),
        (ShellView::ThreatEditor, "THREAT MODEL EDIT"),
        (ShellView::PromptsEditor, "PROMPTS"),
        (ShellView::ActorDetail(1), "ACTOR 1"),
        (ShellView::Runs, "RUN TIMELINE"),
        (
            ShellView::RunDiff {
                left: "run-left".to_string(),
                right: "run-right".to_string(),
            },
            "RUN DIFF",
        ),
        (ShellView::Replay("run-1".to_string()), "REPLAY"),
        (ShellView::Trace("run-1".to_string()), "TRACE"),
        (ShellView::Help, "HELP"),
        (ShellView::Config, "CONFIG"),
        (ShellView::Tools, "TOOLS"),
        (
            ShellView::Options(crate::app::OptionsView {
                tool_name: "sast:scan".to_string(),
                filter: crate::app::OptionsFilter::Standard,
            }),
            "OPTIONS",
        ),
        (ShellView::SastTasks, "SAST TASKS"),
        (ShellView::Context, "CONTEXT"),
        (ShellView::ProjectModel, "PROJECT MODEL"),
        (ShellView::StrategyQueue, "STRATEGY QUEUE"),
        (ShellView::Workspace, "WORKSPACE"),
        (ShellView::KnowledgeBase, "KB ATTACHMENTS"),
        (ShellView::FailureHandoff, "FAILURE HANDOFF"),
        (ShellView::AgentChat, "AGENT"),
        (ShellView::History, "COMMAND HISTORY"),
        (ShellView::Story, "SESSION STORY"),
        (ShellView::Auth, "PROVIDERS"),
        (ShellView::Cost, "BUDGETS"),
        (ShellView::Patch("F-0001".to_string()), "PATCH"),
        (ShellView::Pwn, "PWN TARGET"),
    ];

    for (view, expected) in cases {
        let backend = TestBackend::new(110, 26);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.focused_module = Some("semgrep".to_string());
        // The Workbench command center is the one box-drawing primary surface
        // (bordered panes); every other view stays line-based.
        let is_workbench = matches!(view, ShellView::Workbench);
        app.shell_view = view;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains(expected), "missing {expected}");
        if !is_workbench {
            assert!(!rendered.contains("┌"), "{expected} drew a box");
        }
    }
}

#[test]
fn renders_pwn_dashboard_with_state_and_rounds() {
    let backend = TestBackend::new(110, 28);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Pwn;
    app.pwn_view.target = Some(std::path::PathBuf::from("./chal"));
    app.pwn_view.profile_snapshot = Some(serde_json::json!({
        "arch": "x86-64",
        "needed": ["libc.so.6"]
    }));
    app.pwn_view.state_snapshot = Some(serde_json::json!({
        "primitives": [{
            "kind": "leak",
            "confidence": 0.75,
            "evidence": "controlled pointer disclosure",
            "remoteSafe": true
        }]
    }));
    app.pwn_view.auto_solve_snapshot = Some(serde_json::json!({
        "llmPlanner": {
            "iterations": [{
                "round": 0,
                "decision": {
                    "actions": [{"operation": "reverse-function", "function": "main"}]
                }
            }]
        }
    }));
    app.pwn_view.reverse_snapshots.push(serde_json::json!({
        "function": "main",
        "revng": {"ok": true, "output": "void main() { puts(\"hi\"); }"},
        "dangerousIo": ["puts"]
    }));

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());
    assert!(rendered.contains("PWN TARGET"));
    assert!(rendered.contains("leak"));
    assert!(rendered.contains("round 0"));
    assert!(rendered.contains("revng ok"));
}

fn buffer_row_text(buffer: &Buffer, width: u16, y: u16) -> String {
    let mut text = String::new();
    for x in 0..width {
        text.push_str(buffer[(x, y)].symbol());
    }
    text
}

fn assert_strict_plain_80(rendered: &str) {
    assert_strict_plain_width(rendered, 80);
}

fn assert_strict_plain_width(rendered: &str, width: usize) {
    assert!(
        !rendered.contains('\u{1b}'),
        "plain output contained ANSI escape: {rendered:?}"
    );
    assert!(
        !rendered
            .chars()
            .any(|ch| ('\u{2500}'..='\u{257f}').contains(&ch)),
        "plain output contained box drawing: {rendered:?}"
    );
    for line in rendered.lines() {
        assert!(
            line.chars().count() <= width,
            "plain line exceeded {width} columns: {line:?}"
        );
    }
}

#[test]
fn header_hides_cost_at_zero_and_compacts_at_higher_amounts() {
    // P4-7: at session_cost_usd == 0 the header used to render
    // `cost $0.0000` (12 chars) which pushed `model unconfigured` off
    // the right edge of 120-column terminals. Verify it's hidden until
    // a tool charges, and that the format compacts above $0.01.
    assert_eq!(format_session_cost(0.0042), "$0.0042");
    assert_eq!(format_session_cost(0.42), "$0.42");
    assert_eq!(format_session_cost(12.345), "$12.35");
    assert_eq!(format_session_cost(245.6), "$246");

    let backend = TestBackend::new(120, 40);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.session_cost_usd = 0.0;
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());
    assert!(
        !rendered.contains("cost $0.0000"),
        "header still rendered zero-cost noise: {rendered}"
    );

    // Once a real cost is reported we expect the cost segment back.
    app.session_cost_usd = 0.42;
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());
    assert!(rendered.contains("cost:$0.42"));
}

#[test]
fn module_run_error_wraps_on_word_boundaries() {
    // P4-4: previously the SCAN PROGRESS panel rendered the scan error
    // as a single line that was truncated mid-word, hiding the
    // actionable install command. Verify the renderer now uses
    // wrap_text so the next-step suggestion survives the wrap.
    use std::path::PathBuf;
    let backend = TestBackend::new(72, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::ModuleRun;
    app.scan = Some(ScanPanelState {
        run_id: Some("abc1234".to_string()),
        target: PathBuf::from("./repo"),
        stage: "failed".to_string(),
        findings_count: 0,
        running: false,
        abort_requested: false,
        error: Some(
            "semgrep: could not find scanner binary \"semgrep\". Install Semgrep \
                 (for example `pipx install semgrep` or `brew install semgrep`)."
                .to_string(),
        ),
    });
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());
    assert!(rendered.contains("pipx install semgrep"));
    assert!(rendered.contains("brew install semgrep"));
}

#[test]
fn prompt_segments_highlight_follows_app_cursor() {
    // Cursor at the END of the input — the cursor cell is the trailing
    // glyph, before_cursor contains the whole input.
    let segments = prompt_segments("kuzushi> ", "abcdef", 6, 40, " ");
    assert_eq!(segments.before_cursor, "abcdef");
    assert_eq!(segments.cursor_text, " ");
    assert_eq!(segments.after_cursor, "");

    // Cursor in the middle — the cursor cell is the char it sits on.
    let segments = prompt_segments("kuzushi> ", "abcdef", 4, 40, " ");
    assert_eq!(segments.before_cursor, "abcd");
    assert_eq!(segments.cursor_text, "e");
    assert_eq!(segments.after_cursor, "f");

    // Cursor at the start — first char becomes the cursor cell.
    let segments = prompt_segments("kuzushi> ", "abcdef", 0, 40, " ");
    assert_eq!(segments.before_cursor, "");
    assert_eq!(segments.cursor_text, "a");
    assert_eq!(segments.after_cursor, "bcdef");

    // Cursor past the end is clamped to len so we don't panic on stale
    // indices coming from history-restore races.
    let segments = prompt_segments("kuzushi> ", "abc", 99, 40, " ");
    assert_eq!(segments.before_cursor, "abc");
    assert_eq!(segments.cursor_text, " ");
}

#[test]
fn view_status_segment_reflects_actual_view_not_focused_module() {
    // P1-2: previously the bottom status footer always read "catalog"
    // while the user was on Help / Tools / Findings. Verify the helper
    // returns the real view label so the status reflects what the user
    // actually sees.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Help;
    assert_eq!(view_status_segment(&app), "help");

    app.shell_view = ShellView::Catalog;
    assert_eq!(view_status_segment(&app), "modules");

    app.shell_view = ShellView::Tools;
    assert_eq!(view_status_segment(&app), "tools");

    app.shell_view = ShellView::Workbench;
    assert_eq!(view_status_segment(&app), "workbench");

    app.shell_view = ShellView::Threat(ThreatView::Stride);
    assert_eq!(view_status_segment(&app), "threats:stride");

    app.shell_view = ShellView::Runs;
    assert_eq!(view_status_segment(&app), "run-timeline");

    app.shell_view = ShellView::FailureHandoff;
    assert_eq!(view_status_segment(&app), "failure-handoff");

    // Module view still surfaces the focused module so operators can
    // see which module they're driving.
    app.focused_module = Some("semgrep".to_string());
    app.shell_view = ShellView::Module;
    assert_eq!(view_status_segment(&app), "semgrep");
}

fn line_text(line: &Line<'_>) -> String {
    line.spans.iter().map(|s| s.content.as_ref()).collect()
}

#[test]
fn progress_bar_line_matches_design_glyphs_and_count() {
    let line = progress_bar_line(
        "semgrep",
        612,
        612,
        "done · 18 raw hits",
        ProgressKind::Done,
    );
    let text = line_text(&line);
    assert!(text.contains("semgrep"));
    assert!(text.contains("[████████████████████████]"));
    assert!(text.contains("612/612"));
    assert!(text.contains("done · 18 raw hits"));
}

#[test]
fn progress_bar_line_partial_fills_proportionally() {
    let line = progress_bar_line("agentic-sast", 87, 120, "tracing…", ProgressKind::Active);
    let text = line_text(&line);
    // 87/120 = 0.725; round(0.725 * 24) = 17 filled, 7 empty
    let filled = text.matches('█').count();
    let empty = text.matches('░').count();
    assert_eq!(filled, 17, "expected 17 filled bars: {text:?}");
    assert_eq!(empty, 7, "expected 7 empty bars: {text:?}");
    assert!(text.contains("87/120"));
}

#[test]
fn progress_bar_line_zero_total_renders_empty() {
    let line = progress_bar_line("idle", 0, 0, "queued", ProgressKind::Failing);
    let text = line_text(&line);
    assert_eq!(text.matches('█').count(), 0);
    assert_eq!(text.matches('░').count(), 24);
}

#[test]
fn section_header_uppercases_and_pads_dashes() {
    // Per `design/mockups/_shared.jsx::sectionHeader`, the header lays
    // out as ` ── LABEL ──...─` (leading space, subtle rule, label,
    // subtle fill).  Uppercasing the label is preserved so e.g.
    // `findings · 11 triaged` still reads as `FINDINGS · 11 TRIAGED`.
    let line = section_header_line("findings · 11 triaged", 60);
    let text = line_text(&line);
    assert!(text.starts_with(" ── FINDINGS · 11 TRIAGED "));
    assert!(text.ends_with("─"));
    assert_eq!(text.chars().count(), 60);
}

#[test]
fn next_action_line_splits_run_tool_into_warn_primary_accent_muted() {
    // `design/mockups/catalog.jsx` paints the catalog NEXT line in four
    // colors: c-warn glyph, c-primary verb, c-accent tool name,
    // c-primary continuation, c-muted ambient suffix after ` — `.
    let line = next_action_line(
        "Run sast:scan against ~/work/acme-checkout — never run here, 0 findings on record",
        120,
    );

    // Verify the textual ordering by colour bucket — collect span
    // contents grouped by foreground style so the test fails loudly
    // if a future refactor flattens them back into one primary span.
    let mut buckets: Vec<(String, String)> = Vec::new();
    for span in &line.spans {
        let role = if span.style == theme::warn() {
            "warn"
        } else if span.style == theme::accent() {
            "accent"
        } else if span.style == theme::muted() {
            "muted"
        } else if span.style == theme::primary() {
            "primary"
        } else {
            "other"
        };
        buckets.push((role.to_string(), span.content.to_string()));
    }

    // Glyph + tool name + ambient suffix all show up in the right roles.
    assert!(
        buckets
            .iter()
            .any(|(role, text)| role == "warn" && text.contains("▸ NEXT")),
        "warn glyph missing: {buckets:?}"
    );
    assert!(
        buckets
            .iter()
            .any(|(role, text)| role == "accent" && text == "sast:scan"),
        "accent tool name missing: {buckets:?}"
    );
    assert!(
        buckets
            .iter()
            .any(|(role, text)| role == "muted" && text.contains("never run here")),
        "muted suffix missing: {buckets:?}"
    );
}

#[test]
fn plan_card_keybind_row_drops_bracket_chrome() {
    // The plan-card keybind row used to advertise `[j/k] move
    // [space] toggle [y] apply active [n] discard`. The mockups and
    // the rest of the shell use unbracketed `<key> <hint>` pairs
    // (see `keybindings_line` + `design/mockups/plan.jsx`).  Verify
    // the new spans reach the buffer without `[ ]` chrome.
    use crate::app::{PlanChange, PlanProposal};
    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.pending_plan = Some(PlanProposal {
        goal: "demo".to_string(),
        summary: "demo summary".to_string(),
        changes: vec![PlanChange::Note {
            text: "stub change".to_string(),
        }],
        unsupported: vec![],
    });

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("PLAN"));
    assert!(rendered.contains("j/k move"));
    assert!(rendered.contains("space toggle"));
    assert!(rendered.contains("y apply active"));
    assert!(rendered.contains("n discard"));
    assert!(!rendered.contains("[j/k]"), "stale bracket: {rendered}");
    assert!(!rendered.contains("[space]"), "stale bracket: {rendered}");
    assert!(!rendered.contains("[y]"), "stale bracket: {rendered}");
    assert!(!rendered.contains("[n]"), "stale bracket: {rendered}");
}

#[test]
fn prereq_plan_card_shows_cached_missing_writes_risk_cost_and_actions() {
    let tmp = tempfile::tempdir().unwrap();
    let context_snapshot_path = target_context_snapshot_path(tmp.path());
    std::fs::create_dir(context_snapshot_path.parent().unwrap()).unwrap();
    std::fs::write(context_snapshot_path, "{}\n").unwrap();
    let backend = TestBackend::new(132, 34);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    let chain = PrereqChain::new(
        prereq_steps_for("carlini-threat-hunt:run", tmp.path()),
        "carlini-threat-hunt:run".to_string(),
        serde_json::json!({}),
        None,
    );
    app.pending_prereq_prompt = Some(chain.plan());
    app.shell_view = ShellView::ModuleRun;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("PREREQUISITE PLAN"));
    assert!(rendered.contains("carlini-threat-hunt:run"));
    assert!(rendered.contains("cached"));
    assert!(rendered.contains("missing"));
    assert!(rendered.contains("context snapshot"));
    assert!(rendered.contains("threat model"));
    assert!(rendered.contains("writes"));
    assert!(rendered.contains(".kuzushi"));
    assert!(rendered.contains("model-backed analysis"));
    assert!(rendered.contains("token cost unknown"));
    assert!(rendered.contains("a approve"));
    assert!(rendered.contains("r reuse cached"));
    assert!(rendered.contains("g regenerate"));
    assert!(rendered.contains("n cancel"));
}

#[test]
fn prereq_plan_card_explains_invalid_artifacts_before_reuse() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(target_context_snapshot_path(tmp.path())).unwrap();
    let backend = TestBackend::new(132, 34);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    let chain = PrereqChain::new(
        prereq_steps_for("sast:scan", tmp.path()),
        "sast:scan".to_string(),
        serde_json::json!({}),
        None,
    );
    app.pending_prereq_prompt = Some(chain.plan());
    app.shell_view = ShellView::ModuleRun;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("invalid"));
    assert!(rendered.contains("invalid artifact"));
    assert!(rendered.contains("approve"));
    assert!(rendered.contains("regenerate"));
}

#[test]
fn plain_prereq_plan_has_no_ansi_or_box_drawing() {
    let tmp = tempfile::tempdir().unwrap();
    let context_snapshot_path = target_context_snapshot_path(tmp.path());
    std::fs::create_dir(context_snapshot_path.parent().unwrap()).unwrap();
    std::fs::write(context_snapshot_path, "{}\n").unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    let chain = PrereqChain::new(
        prereq_steps_for("carlini-threat-hunt:run", tmp.path()),
        "carlini-threat-hunt:run".to_string(),
        serde_json::json!({}),
        None,
    );
    app.pending_prereq_prompt = Some(chain.plan());

    let rendered = render_plain_app(&app, 80);

    assert!(rendered.contains("PREREQUISITE PLAN"));
    assert!(rendered.contains("cached context snapshot"));
    assert!(rendered.contains("missing threat model"));
    assert!(rendered.contains("actions: approve | reuse cached | regenerate | cancel"));
    assert!(rendered.contains(".kuzushi"));
    assert_strict_plain_80(&rendered);
}

#[test]
fn module_run_renders_live_activity_in_body_and_status_strip() {
    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::ModuleRun;
    app.live_activity = Some(LiveActivity::new(
        LiveActivityPhase::Thinking,
        "triage:run",
        "asking model to triage persisted findings",
    ));

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("LIVE ACTIVITY"));
    assert!(rendered.contains("thinking"));
    assert!(rendered.contains("triage:run"));
    assert!(rendered.contains("activity"));
    assert!(!rendered.contains("tool: active"));
}

#[test]
fn plain_live_activity_has_no_ansi_or_box_drawing() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let detail = format!("writes {}", threat_model_relative_path());
    app.live_activity = Some(LiveActivity::new(
        LiveActivityPhase::WritingArtifact,
        "threat-model:build",
        detail,
    ));

    let rendered = render_plain_app(&app, 80);

    assert!(rendered.contains("LIVE ACTIVITY"));
    assert!(rendered.contains("phase: writing artifact"));
    assert!(rendered.contains("subject: threat-model:build"));
    assert!(rendered.contains(&format!("detail: writes {}", threat_model_relative_path())));
    assert_strict_plain_80(&rendered);
}

#[test]
fn command_list_line_accents_each_command_with_subtle_separators() {
    // `command_list_line` builds the inline next-action hint that
    // appears at the bottom of many views (workspace, agent-chat,
    // history, kb).  The mockup paints commands in c-accent and
    // the ` · ` separator in c-subtle.
    let line = command_list_line(&["scan .", "findings", "back"], 120);
    let mut accent_chunks = 0usize;
    let mut subtle_chunks = 0usize;
    for span in &line.spans {
        if span.style == theme::accent() {
            accent_chunks += 1;
        } else if span.style == theme::subtle() {
            subtle_chunks += 1;
        }
    }
    assert_eq!(accent_chunks, 3, "expected 3 accent commands");
    assert_eq!(subtle_chunks, 2, "expected 2 subtle middot separators");
}

#[test]
fn command_list_line_truncates_with_ellipsis_when_width_runs_out() {
    // Narrow width should drop trailing commands behind a subtle `…`
    // rather than overflow the row.
    let line = command_list_line(&["aaaaaaaa", "bbbbbbbb", "cccccccc"], 12);
    let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
    assert!(text.contains("…"), "missing ellipsis: {text}");
}

#[test]
fn runs_view_tints_status_column_per_mockup() {
    // `design/mockups/runs.jsx::r` paints the status cell with a
    // status-aware colour (complete → c-success, paused → c-warn,
    // failed → c-danger).  The Ratatui runs view used to leave
    // that column in default style.  Verify `runs_lines` puts the
    // success tint on a non-erroring scan and keeps the run-id
    // accent.
    let backend = TestBackend::new(120, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.scan = Some(crate::app::ScanPanelState {
        run_id: Some("r-08e1aa".to_string()),
        target: std::path::PathBuf::from("/tmp/demo"),
        stage: "complete".to_string(),
        findings_count: 11,
        running: false,
        abort_requested: false,
        error: None,
    });
    app.shell_view = ShellView::Runs;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("RUN TIMELINE"));
    assert!(rendered.contains("r-08e1aa"));
    assert!(rendered.contains("11"));
    // Verify by inspecting the line spans directly so we know the
    // status text is wearing the success style and the run id keeps
    // its accent style.
    let area = ratatui::layout::Rect::new(0, 0, 120, 22);
    let lines = runs_lines(&app, area);
    let row = lines
        .iter()
        .find(|line| line_text(line).contains("r-08e1aa"))
        .expect("run row missing");
    let mut saw_run_accent = false;
    let mut saw_status_success = false;
    for span in &row.spans {
        if span.content.contains("r-08e1aa") && span.style == theme::accent() {
            saw_run_accent = true;
        }
        if span.style == theme::success() {
            saw_status_success = true;
        }
    }
    assert!(saw_run_accent, "run id should be accent: {row:?}");
    assert!(saw_status_success, "status should be success: {row:?}");
}

#[test]
fn transcript_finding_line_tints_severity_per_mockup() {
    // `design/mockups/findings.jsx::findingRow` puts the severity in a
    // severity-tinted span, the rule-id in c-accent, and the location
    // in c-muted.  Verify `transcript_finding_line` builds the same
    // four-color split (warn glyph, severity tint, accent rule-id,
    // muted location).
    let line = transcript_finding_line(
        SeverityTone::Critical,
        "CRITICAL",
        "demo.rule",
        "src/x.rs:142",
    );
    let mut roles: Vec<&str> = Vec::new();
    for span in &line.spans {
        roles.push(if span.style == theme::warn() {
            "warn"
        } else if span.style == theme::severity_tone(SeverityTone::Critical) {
            "sev-critical"
        } else if span.style == theme::accent() {
            "accent"
        } else if span.style == theme::muted() {
            "muted"
        } else {
            "other"
        });
    }
    assert!(roles.contains(&"warn"), "warn glyph missing: {roles:?}");
    assert!(
        roles.contains(&"sev-critical"),
        "critical severity tint missing: {roles:?}"
    );
    assert!(
        roles.contains(&"accent"),
        "accent rule-id missing: {roles:?}"
    );
    assert!(
        roles.contains(&"muted"),
        "muted location missing: {roles:?}"
    );
}

#[test]
fn runs_view_lists_past_runs_from_run_json_with_summary_fallback() {
    // Mockup parity: `design/mockups/runs.jsx` shows past runs as a
    // table with status tinting.  Verify the run view model prefers
    // canonical `run.json`, keeps `summary.json` fallback, and renders
    // one styled row per past run.
    let tmp = tempfile::tempdir().unwrap();
    let canonical_run_dir = ui_run_dir(Some(tmp.path()), "r-2026-05-06T14-31");
    let legacy_run_dir = ui_run_dir(Some(tmp.path()), "r-2026-05-06T15-18");
    std::fs::create_dir_all(&canonical_run_dir).unwrap();
    std::fs::create_dir_all(&legacy_run_dir).unwrap();
    std::fs::write(
        canonical_run_dir.join("run.json"),
        r#"{"status":"completed","findings":18,"target":"~/work/acme-checkout"}"#,
    )
    .unwrap();
    std::fs::write(
        legacy_run_dir.join("summary.json"),
        r#"{"status":"failed","findings":0,"target":"~/work/acme-checkout"}"#,
    )
    .unwrap();

    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(tmp.path().to_path_buf());
    app.shell_view = ShellView::Runs;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("RUN TIMELINE"));
    // Both past runs reach the buffer with disambiguating short labels.
    assert!(
        rendered.contains("r-2026") && rendered.contains("T14-31"),
        "missing run ID parts in {rendered}"
    );
    assert!(rendered.contains("completed"));
    assert!(rendered.contains("failed"));
    assert!(rendered.contains("18"));
    assert!(rendered.contains("replay <runId>"));
}

#[test]
fn run_diff_view_renders_added_removed_findings_and_revisions() {
    let tmp = tempfile::tempdir().unwrap();
    write_run_diff_fixture(
        tmp.path(),
        "run-left",
        "abcdef123456",
        serde_json::json!([
            {"fingerprint":"same","title":"shared","severity":"high","filePath":"src/lib.rs","startLine":10,"tool":"semgrep"},
            {"fingerprint":"removed","title":"removed item","severity":"medium","filePath":"src/old.rs","startLine":20,"tool":"codeql"}
        ]),
    );
    write_run_diff_fixture(
        tmp.path(),
        "run-right",
        "123456789abc",
        serde_json::json!([
            {"fingerprint":"same","title":"shared","severity":"high","filePath":"src/lib.rs","startLine":10,"tool":"semgrep"},
            {"fingerprint":"added","title":"added item","severity":"critical","filePath":"src/new.rs","startLine":30,"tool":"joern"}
        ]),
    );
    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(tmp.path().to_path_buf());
    app.shell_view = ShellView::RunDiff {
        left: "run-left".to_string(),
        right: "run-right".to_string(),
    };

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("RUN DIFF"));
    assert!(rendered.contains("rev:abcdef1"));
    assert!(rendered.contains("rev:1234567"));
    assert!(rendered.contains("ADDED IN RIGHT"));
    assert!(rendered.contains("added item"));
    assert!(rendered.contains("REMOVED FROM RIGHT"));
    assert!(rendered.contains("removed item"));
}

fn write_run_diff_fixture(
    root: &std::path::Path,
    run_id: &str,
    sha: &str,
    findings: serde_json::Value,
) {
    let run_dir = ui_run_dir(Some(root), run_id);
    std::fs::create_dir_all(&run_dir).unwrap();
    std::fs::write(
        run_dir.join("run.json"),
        serde_json::json!({
            "status": "completed",
            "targetGit": {"sha": sha, "branch": "main", "dirty": false},
            "target": root.display().to_string()
        })
        .to_string(),
    )
    .unwrap();
    std::fs::write(run_dir.join("findings.json"), findings.to_string()).unwrap();
}

#[test]
fn catalog_j_k_moves_row_cursor_and_highlights_row() {
    // `design/mockups/catalog.jsx` advertises `j/k row` and shows the
    // focused row with `▌` accent + c-sel background.  Verify that
    // pressing `j` moves the cursor and that the catalog renders the
    // cursor row with the `▌` glyph (catalog_module_row's selection
    // form starts the row with `▌ `).
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let backend = TestBackend::new(120, 36);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.handle_command(crate::commands::ShellCommand::Modules);

    // Cursor starts at 0; `j` advances it.
    let before = app.catalog_cursor;
    app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()));
    assert_eq!(app.catalog_cursor, before + 1);

    // `k` reverses; from row 1 back to 0.
    app.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::empty()));
    assert_eq!(app.catalog_cursor, before);

    // Render after a `j` press; the catalog body should contain the
    // cursor `▌` glyph at least once.
    app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()));
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());
    assert!(rendered.contains("▌"), "cursor glyph missing: {rendered}");
}

#[test]
fn catalog_enter_runs_use_for_cursor_row() {
    // Pressing Enter on the catalog with empty input dispatches
    // `use <module>` for whatever row j/k put the cursor on, per
    // `design/mockups/catalog.jsx::footer` (`enter run` keybind).
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = ShellApp::new(V2Config::default(), None);
    app.handle_command(crate::commands::ShellCommand::Modules);
    app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()));
    let cursor_id = app.catalog_cursor_module_id().expect("cursor id");
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    // After Enter, the focused module should be the cursor row.
    assert_eq!(app.focused_module.as_deref(), Some(cursor_id.as_str()));
}

#[test]
fn catalog_g_and_uppercase_g_jump_cursor_to_bounds() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = ShellApp::new(V2Config::default(), None);
    app.handle_command(crate::commands::ShellCommand::Modules);
    let total = app.catalog_module_count();
    assert!(total > 0);

    // G jumps to last row.
    app.handle_key(KeyEvent::new(KeyCode::Char('G'), KeyModifiers::empty()));
    assert_eq!(app.catalog_cursor, total - 1);

    // g jumps to first.
    app.handle_key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::empty()));
    assert_eq!(app.catalog_cursor, 0);
}

#[test]
fn top_status_strip_shows_stage_spinner_while_scan_runs() {
    // `design/mockups/sast-running.jsx::customStrip` adds a `stage ⠿
    // running` segment to the top strip while a worker ticks.  Verify
    // the segment appears for a running scan and disappears when idle.
    let backend = TestBackend::new(120, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);

    // Idle: no stage segment.
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let idle = format!("{:?}", terminal.backend().buffer());
    assert!(
        !idle.contains("stage "),
        "stage shouldn't show idle: {idle}"
    );

    // Running: stage segment with spinner glyph.
    app.scan = Some(crate::app::ScanPanelState {
        run_id: Some("r-now".to_string()),
        target: std::path::PathBuf::from("."),
        stage: "running".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    });
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let running = format!("{:?}", terminal.backend().buffer());
    assert!(running.contains("stage:"), "stage missing: {running}");
    assert!(running.contains("running"));
    // Any of the SPINNER_FRAMES shows up.
    let saw_spinner = SPINNER_FRAMES.iter().any(|f| running.contains(f));
    assert!(saw_spinner, "spinner glyph missing: {running}");
}

#[test]
fn cost_view_renders_budget_bar_and_session_spend() {
    // `/cost` (`design/mockups/cost.jsx`) shows BUDGETS bars +
    // SPEND key/values.  Verify both sections render and the bar
    // graphics + percentage reach the buffer.
    let backend = TestBackend::new(120, 26);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.session_cost_usd = 1.42;
    app.session_budget_usd = Some(5.0);
    app.last_tool_cost_usd = Some(0.18);
    app.shell_view = ShellView::Cost;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("BUDGETS"));
    assert!(rendered.contains("SPEND"));
    assert!(rendered.contains("█"));
    assert!(rendered.contains("░"));
    assert!(rendered.contains("$1.42"));
    assert!(rendered.contains("$5.00"));
    // 1.42 / 5.00 = 28.4% → 28%, success-tinted (< 85%).
    assert!(rendered.contains("28%"));
}

#[test]
fn auth_view_renders_providers_model_and_spend_sections() {
    // `/auth` should land on a dedicated ShellView::Auth surface
    // matching `design/mockups/auth.jsx` — providers list + effective
    // model + session spend.
    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(
        V2Config {
            model: Some("openai:gpt-4.1".to_string()),
            ..V2Config::default()
        },
        None,
    );
    app.session_cost_usd = 0.42;
    app.shell_view = ShellView::Auth;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("PROVIDERS"));
    assert!(rendered.contains("MODEL"));
    assert!(rendered.contains("SPEND"));
    assert!(rendered.contains("openai:gpt-4.1"));
    assert!(rendered.contains("$0.42"));
    assert!(rendered.contains("auth login openai"));
    assert!(rendered.contains("github-copilot"));
}

#[test]
fn auth_view_renders_latest_oauth_flow_state() {
    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Auth;
    app.auth_login = Some(AuthLoginView {
        provider: "openai".to_string(),
        method: "headless".to_string(),
        status: "waiting".to_string(),
        detail: "OpenAI device code flow".to_string(),
        store_path: "~/.kuzushi/oauth-credentials.json".to_string(),
    });

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("OAUTH"));
    assert!(rendered.contains("headless"));
    assert!(rendered.contains("OpenAI device code flow"));
    assert!(!rendered.contains("codex"));
    assert!(rendered.contains("oauth-credentials.json"));
}

#[test]
fn auth_view_stacks_and_wraps_on_narrow_terminals() {
    // Narrow panes (tmux splits, mobile sshd) used to hard-clip every
    // ` label value · label value` row mid-word ("method brows",
    // "backe") and ellipsize the rotate commands into unusable
    // fragments. The view must reflow instead: kv rows stack, prose and
    // hints wrap, the store path keeps its tail, and every recovery
    // command survives.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Auth;
    app.auth_login = Some(AuthLoginView {
        provider: "openai".to_string(),
        method: "browser".to_string(),
        status: "connected".to_string(),
        detail: "credentials saved; validated against the provider".to_string(),
        store_path: "/Users/operator/.kuzushi/oauth-credentials.json".to_string(),
    });

    let width: u16 = 36;
    let area = ratatui::layout::Rect::new(0, 0, width, 50);
    let lines = auth_lines(&app, area);
    let texts: Vec<String> = lines.iter().map(line_text).collect();
    let rendered = texts.join("\n");

    for text in &texts {
        assert!(
            text.trim_end().chars().count() <= width as usize,
            "line overflows {width} cols and would clip: {text:?}"
        );
    }
    // kv values stack as whole words instead of clipping mid-word.
    assert!(rendered.contains("method    browser"));
    assert!(rendered.contains("status    connected"));
    // Prose wraps; the tail of the message is still readable.
    assert!(rendered.contains("provider"));
    assert!(rendered.contains("validated against"));
    // The store path keeps its useful tail, not the home-dir prefix.
    assert!(rendered.contains("oauth-credentials.json"));
    // Rotate hints wrap — the pasteable command survives in full.
    assert!(rendered.contains("re-launch kuzushi"));
    // Every recovery command is reachable; none hide behind an ellipsis.
    for command in [
        "auth login openai browser",
        "auth login github-copilot",
        "model <provider:id>",
        "back",
    ] {
        assert!(rendered.contains(command), "missing command: {command}");
    }
}

#[test]
fn home_view_shows_journey_rail_and_phase_chip_with_target() {
    // The engagement spine must be ambient: the home view carries the
    // 組 map → 崩 hunt → 作 confirm → 掛 fix rail and the idle footer a
    // compact journey chip whenever a target is active.
    let dir = tempfile::tempdir().expect("temp target");
    let backend = TestBackend::new(120, 34);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(dir.path().to_path_buf());
    app.shell_view = ShellView::Home;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("組 map"), "rail shows map phase");
    assert!(rendered.contains("崩 hunt"), "rail shows hunt phase");
    assert!(rendered.contains("掛 fix"), "rail shows fix phase");
    assert!(rendered.contains("組 map 1/4"), "footer phase chip");
    assert!(
        rendered.contains("Run next"),
        "NEXT action speaks the journey verb"
    );
}

#[test]
fn activity_view_collapses_tasks_pane_for_taskless_runs() {
    // A single-tool run registers no DAG tasks; the 40% TASKS pane would
    // only ever say "(no DAG tasks yet)" while the OUTPUT pane clips its
    // content. Collapse to a full-width OUTPUT pane instead.
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.activity = Some(ActivitySession::new("tool-1"));
    app.shell_view = ShellView::Activity;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(!rendered.contains("no DAG tasks yet"));
    assert!(!rendered.contains("TASKS"));
    assert!(rendered.contains("OUTPUT"));
    assert!(rendered.contains("no task rows — streaming tool output"));
    assert!(rendered.contains("[output focused]"));
}

#[test]
fn activity_view_names_the_running_tool_everywhere_it_matters() {
    // The audit complaint: a taskless run showed an anonymous
    // "(waiting for trace events…)" against a static gallery and the
    // operator couldn't tell whether anything was happening. The header
    // must name the tool with a ticking elapsed counter, the feed must
    // explain the silence, and the footer must offer the cancel path.
    let backend = TestBackend::new(90, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.tool_running = Some("threat-model:build".to_string());
    app.activity = Some(ActivitySession::new("tool-7b7fa744"));
    app.shell_view = ShellView::Activity;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("threat-model:build · running"));
    assert!(rendered.contains("ACTIONS"));
    assert!(rendered.contains("threat-model:build is"));
    assert!(rendered.contains("▸ RUNNING  threat-model:build"));
    assert!(!rendered.contains("waiting for trace events"));
    assert!(!rendered.contains("hover [j/k] to inspect a task"));
}

#[test]
fn target_picker_renders_candidates_with_cursor_and_hints() {
    let backend = TestBackend::new(120, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target_candidates = vec![
        crate::app::TargetCandidate {
            path: std::path::PathBuf::from("/work/acme"),
            label: ".".to_string(),
            hint: "git repo",
            scope: None,
        },
        crate::app::TargetCandidate {
            path: std::path::PathBuf::from("/work/acme/api"),
            label: "api".to_string(),
            hint: "previous kuzushi target",
            scope: None,
        },
        crate::app::TargetCandidate {
            path: std::path::PathBuf::from("/work/acme/libs/parser"),
            label: "libs/parser".to_string(),
            hint: "git submodule",
            scope: None,
        },
    ];
    app.target_picker_cursor = 1;
    app.shell_view = ShellView::TargetPicker;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("CHOOSE A TARGET"));
    assert!(rendered.contains("git repo"));
    assert!(rendered.contains("> api"), "cursor marks the selected row");
    assert!(rendered.contains("previous kuzushi target"));
    assert!(rendered.contains("git submodule"));
    assert!(
        rendered.contains("target <path>"),
        "manual-path escape hatch"
    );
}

#[test]
fn home_view_without_target_has_no_journey_rail() {
    // No target → no engagement; home keeps the first-run guidance and
    // the rail stays out of the way.
    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Home;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(!rendered.contains("組 map"));
    assert!(!rendered.contains("phase:"));
    assert!(rendered.contains("quickstart"));
}

#[test]
fn auth_provider_rows_drop_detail_to_second_line_when_narrow() {
    // At full width the detail cell rides the same row; when the row
    // would overflow, the detail drops to an indented second line
    // instead of vanishing off the right edge.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Auth;

    let area = ratatui::layout::Rect::new(0, 0, 36, 50);
    let rendered = auth_lines(&app, area)
        .iter()
        .map(line_text)
        .collect::<Vec<_>>()
        .join("\n");

    // The anthropic detail ("ANTHROPIC_API_KEY=…; oauth …") cannot fit
    // beside the 16-col name + 11-col status at width 36 — it must
    // appear on its own line rather than being clipped away.
    assert!(rendered.contains("ANTHROPIC_API_KEY="));
}

#[test]
fn transcript_log_line_renders_wall_clock_timestamp_when_present() {
    // `design/mockups/_shared.jsx::logLine` paints each transcript row
    // with a leading `HH:MM:SS` in c-subtle.  Verify the dated path
    // emits a 5-or-8-char timestamp span styled subtle, before the
    // glyph + prefix + body.
    let line = transcript_line_dated(
        "tool",
        "ran semgrep:scan",
        false,
        // 14:32:14 UTC = 14*3600 + 32*60 + 14 = 52334 seconds into the day
        52_334,
    );
    let mut saw_subtle_time = false;
    let mut saw_glyph = false;
    for span in &line.spans {
        if span.content == "14:32:14" && span.style == theme::subtle() {
            saw_subtle_time = true;
        }
        if span.content.contains("⏵") {
            saw_glyph = true;
        }
    }
    assert!(saw_subtle_time, "subtle HH:MM:SS missing: {line:?}");
    assert!(saw_glyph, "transcript glyph missing: {line:?}");
}

#[test]
fn transcript_line_dated_skips_timestamp_when_zero() {
    // Synthetic transcript lines (built inside the renderer for
    // context-free hints) pass `time_secs = 0` and should produce no
    // leading timestamp — keeping those lines terse.
    let line = transcript_line_dated("tool", "synthetic", false, 0);
    for span in &line.spans {
        assert!(
            !span.content.contains(':') || !matches!(span.content.chars().next(), Some('0'..='9')),
            "unexpected timestamp on synthetic line: {span:?}"
        );
    }
}

#[test]
fn throttle_banner_uses_chip_style_per_mockup() {
    // `design/mockups/rate-limited.jsx` paints the throttle banner as
    // ` RATE LIMIT  <source> · <message>` with a warn-tinted chip
    // prefix and a muted message tail.  The Ratatui shell was emitting
    // `⚠ rate limit · <source> · <message>` in one warn span — the
    // chip-style prefix is what the operator's eye locks onto.
    let backend = TestBackend::new(120, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.advisory.throttle = Some(crate::app::ThrottleAdvisory {
        source: "anthropic".to_string(),
        message: "429 retry-after 14s".to_string(),
        since: std::time::Instant::now(),
    });

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("RATE LIMIT"));
    assert!(rendered.contains("anthropic"));
    assert!(rendered.contains("429 retry-after"));
    assert!(
        !rendered.contains("⚠ rate limit"),
        "stale prose banner: {rendered}"
    );
}

#[test]
fn cost_cap_halt_row_drops_bracket_chrome() {
    // The cost-cap halt panel was the last place advertising bracketed
    // key chrome (`[c] continue past cap   [a] abort scan`).  The
    // mockups (e.g. `design/mockups/budget-stop.jsx`) use the same
    // unbracketed `<key> <hint>   <key> <hint>` shape as the keybind
    // footer.  Verify the panel renders the unbracketed form when the
    // budget is halted.
    let backend = TestBackend::new(80, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.advisory.budget_halt = Some(crate::app::BudgetHalt {
        limit_usd: 1.0,
        spent_usd: 1.5,
    });

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("COST CAP HALT"));
    assert!(rendered.contains("continue past cap"));
    assert!(rendered.contains("abort scan"));
    assert!(
        !rendered.contains("[c]"),
        "stale bracket chrome: {rendered}"
    );
    assert!(
        !rendered.contains("[a]"),
        "stale bracket chrome: {rendered}"
    );
}

#[test]
fn cost_cap_halt_renders_compact_fallback_on_short_terminals() {
    let backend = TestBackend::new(80, 4);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.advisory.budget_halt = Some(crate::app::BudgetHalt {
        limit_usd: 1.0,
        spent_usd: 1.5,
    });

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("COST CAP: c=continue"));
    assert!(rendered.contains("a=abort"));
}

#[test]
fn module_detail_renders_options_when_stored_values_exist() {
    // `design/mockups/modules-detail.jsx::s2` shows OPTIONS · N as
    // a section.  Verify storing a value through `option_store`
    // surfaces the option in the panel.
    let backend = TestBackend::new(120, 36);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.option_store.set_value(
        kuzushi_core::OptionScope::Session,
        kuzushi_core::OptionTarget::Tool("sast:scan".to_string()),
        "triage",
        serde_json::json!(true),
    );
    app.focused_module = Some("sast".to_string());
    app.shell_view = ShellView::Module;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("OPTIONS"));
    assert!(rendered.contains("triage"));
    assert!(rendered.contains("true"));
}

#[test]
fn module_detail_lists_prompt_overrides_from_disk() {
    // `design/mockups/modules-detail.jsx::s4` shows PROMPTS · N
    // pulled from `.kuzushi/prompts/<module>/`.  Seed two prompt
    // files and verify both surface as detail rows.
    let tmp = tempfile::tempdir().unwrap();
    let prompts_root = tmp.path().join(".kuzushi/prompts/sast");
    std::fs::create_dir_all(&prompts_root).unwrap();
    std::fs::write(prompts_root.join("system.md"), "system prompt body").unwrap();
    std::fs::write(prompts_root.join("triage.md"), "triage prompt body").unwrap();

    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(tmp.path().to_path_buf());
    app.focused_module = Some("sast".to_string());
    app.shell_view = ShellView::Module;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("PROMPTS"));
    assert!(rendered.contains("system"));
    assert!(rendered.contains("triage"));
}

#[test]
fn prompts_editor_renders_selected_prompt_stack() {
    let tmp = tempfile::tempdir().unwrap();
    let override_path = kuzushi_core::prompt_override_path(tmp.path(), "sast", "triage");
    std::fs::create_dir_all(override_path.parent().unwrap()).unwrap();
    std::fs::write(&override_path, "triage prompt body").unwrap();

    let backend = TestBackend::new(120, 32);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(tmp.path().to_path_buf());
    app.focused_module = Some("sast".to_string());
    app.prompts_cursor = 1;
    app.shell_view = ShellView::PromptsEditor;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("PROMPT STACK"));
    assert!(rendered.contains("triage"));
    assert!(rendered.contains("project override"));
    assert!(rendered.contains("override active"));
    assert!(rendered.contains("sha256:"));
}

#[test]
fn trace_view_renders_steps_from_trace_jsonl() {
    // `design/mockups/trace.jsx::step` shows one row per agent step
    // with kind-tinted column + label + latency + cost.  Seed a
    // small trace.jsonl on disk and verify rows + columns reach
    // the buffer.
    let tmp = tempfile::tempdir().unwrap();
    let runs_root = ui_run_dir(Some(tmp.path()), "r-1");
    std::fs::create_dir_all(&runs_root).unwrap();
    std::fs::write(
            runs_root.join("trace.jsonl"),
            r#"{"n":1,"kind":"plan","label":"plan(F-0012, h=2) → 4-step plan","latency_ms":400,"cost_usd":0.0}
{"n":2,"kind":"tool","label":"kb:fetch a-04","latency_ms":100,"cost_usd":0.0}
{"n":3,"kind":"llm","label":"compose injection candidates","latency_ms":4100,"cost_usd":0.012}
{"n":4,"kind":"refused","label":"write_patch_attempt → policy","latency_ms":0}
"#,
        )
        .unwrap();

    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(tmp.path().to_path_buf());
    app.shell_view = ShellView::Trace("r-1".to_string());

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("TRACE · r-1"));
    assert!(rendered.contains("STEPS"));
    // All 4 step labels.
    assert!(rendered.contains("plan(F-0012"));
    assert!(rendered.contains("kb:fetch"));
    assert!(rendered.contains("compose injection"));
    assert!(rendered.contains("write_patch_attempt"));
    // Latency formatting: 400ms; 4.1s.
    assert!(rendered.contains("400ms"));
    assert!(rendered.contains("4.1s"));
    // Cost.
    assert!(rendered.contains("$0.0120"));
}

#[test]
fn trace_view_empty_when_no_trace_jsonl_on_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = TestBackend::new(120, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(tmp.path().to_path_buf());
    app.shell_view = ShellView::Trace("r-missing".to_string());

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("TRACE · r-missing"));
    assert!(rendered.contains("no trace.jsonl"));
}

#[test]
fn replay_view_prefers_run_json_and_keeps_summary_fallback() {
    let tmp = tempfile::tempdir().unwrap();
    let canonical = ui_run_dir(Some(tmp.path()), "r-canonical");
    let legacy = ui_run_dir(Some(tmp.path()), "r-legacy");
    std::fs::create_dir_all(&canonical).unwrap();
    std::fs::create_dir_all(&legacy).unwrap();
    std::fs::write(canonical.join("run.json"), r#"{"status":"completed"}"#).unwrap();
    std::fs::write(legacy.join("summary.json"), r#"{"status":"complete"}"#).unwrap();

    let canonical_rendered = render_replay_for_target(tmp.path(), "r-canonical");
    assert!(canonical_rendered.contains("run.json"));
    assert!(!canonical_rendered.contains("summary.json (missing)"));

    let legacy_rendered = render_replay_for_target(tmp.path(), "r-legacy");
    assert!(legacy_rendered.contains("summary.json"));
    assert!(!legacy_rendered.contains("run artefacts not on disk"));
}

#[test]
fn replay_view_surfaces_invalid_run_metadata_path() {
    let tmp = tempfile::tempdir().unwrap();
    let run_dir = ui_run_dir(Some(tmp.path()), "r-invalid");
    std::fs::create_dir_all(run_dir.join("run.json")).unwrap();

    let rendered = render_replay_for_target(tmp.path(), "r-invalid");

    assert!(rendered.contains("run.json (not a file)"));
    assert!(!rendered.contains("run artefacts not on disk"));
}

fn render_replay_for_target(target: &std::path::Path, run_id: &str) -> String {
    let backend = TestBackend::new(140, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(target.to_path_buf());
    app.shell_view = ShellView::Replay(run_id.to_string());

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    format!("{:?}", terminal.backend().buffer())
}

#[test]
fn patch_view_renders_rationale_diff_tests_and_guardrail_sections() {
    // `design/mockups/patch.jsx` shows RATIONALE / DIFF / TESTS /
    // GUARDRAIL.  Verify all four reach the buffer with diff lines
    // styled per kind (add → success, del → danger, ctx → muted).
    let backend = TestBackend::new(120, 48);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.pending_patch = Some(crate::app::PendingPatch {
            alias: "F-0001".to_string(),
            rationale: "replace format!() concatenation with sqlx::query!() macro".to_string(),
            side_effect: Some("closes F-0001 (sqli)".to_string()),
            diff: "--- a/apps/api/orders.rs\n+++ b/apps/api/orders.rs\n@@ -138,9 +138,12 @@\n     let q = format!(\"SELECT * FROM orders WHERE id={}\", id);\n-    let row = sqlx::query(&q)\n+    let row = sqlx::query!(\n+        \"SELECT id FROM orders WHERE id = $1\",\n+        id\n+    )\n     .fetch_one(db)\n     .await?;".to_string(),
            tests: vec![
                ("orders::tests::rejects_sqli_payload".to_string(), "1 OR 1=1 → BadId".to_string()),
                ("orders::tests::happy_path_uuid".to_string(), "valid uuid → row".to_string()),
            ],
            guardrail: Some("approval.patches = human-required".to_string()),
            staged_at: Some(ui_run_artifact_relative_path("r-2113", "patch.diff")),
        });
    app.shell_view = ShellView::Patch("F-0001".to_string());

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    // All four sections.
    assert!(rendered.contains("RATIONALE"));
    assert!(rendered.contains("DIFF"));
    assert!(rendered.contains("TESTS"));
    assert!(rendered.contains("GUARDRAIL"));
    // Rationale + side-effect.
    assert!(rendered.contains("sqlx::query!()"));
    assert!(rendered.contains("side-effect"));
    // Diff content + summary.
    assert!(rendered.contains("apps/api/orders.rs"));
    assert!(rendered.contains("@@"));
    assert!(rendered.contains("rejects_sqli_payload"));
    // Diff summary in the divider — at least one file + add count.
    assert!(rendered.contains("1 file"));
    // Tests row.
    assert!(rendered.contains("happy_path_uuid"));
    // Guardrail action row.
    assert!(rendered.contains("/patch apply"));
    // Staged-at footer.
    assert!(rendered.contains("staged at"));
}

#[test]
fn patch_view_empty_state_when_no_patch_pending() {
    let backend = TestBackend::new(120, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Patch("F-0042".to_string());

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("PATCH · F-0042 · empty"));
    assert!(rendered.contains("∅"));
    assert!(rendered.contains("no patch staged"));
    assert!(rendered.contains("patch:run"));
    assert!(rendered.contains(".kuzushi/runs/"));
}

#[test]
fn patch_diff_summary_counts_files_adds_and_dels() {
    let summary = patch_diff_summary(
        "--- a/file1\n+++ b/file1\n@@ -1,3 +1,4 @@\n+added\n-removed\n ctx\n+added2",
    );
    assert_eq!(summary.files, 1);
    assert_eq!(summary.adds, 2);
    assert_eq!(summary.dels, 1);
}

#[test]
fn confirm_card_renders_tool_target_and_y_n_action_row() {
    // `design/mockups/confirm-dialog.jsx` paints CONFIRM gates with
    // a warn header, tool/target/rationale rows, and a y/Y/n/Esc/N action
    // row.  Verify each lands in the buffer when the gate is pending.
    let backend = TestBackend::new(120, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.advisory.pending_confirm = Some(crate::app::PendingConfirm {
        kind: crate::app::ConfirmKind::NetworkEgress,
        tool: "sandbox:run".to_string(),
        target: "curl https://refund.acme/api/internal/balances".to_string(),
        rationale: Some("verify F-0012 reachability".to_string()),
        allowlist: Some("refund.acme on project allowlist".to_string()),
        actor: Some("attacker".to_string()),
        remembered: false,
    });

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("CONFIRM"));
    assert!(rendered.contains("network egress"));
    assert!(rendered.contains("sandbox:run"));
    assert!(rendered.contains("curl https://refund.acme"));
    assert!(rendered.contains("verify F-0012"));
    assert!(rendered.contains("refund.acme on project allowlist"));
    assert!(rendered.contains("allow once"));
    assert!(rendered.contains("n/Esc"));
    assert!(rendered.contains("deny once"));
    assert!(rendered.contains("deny + add to denylist"));
}

#[test]
fn confirm_card_destructive_kind_renders_unconditional_refusal() {
    // Destructive verbs (`rm -rf`, `git push --force`, etc.) get a
    // RED header + REFUSED · destructive verb label + the
    // unconditional-refusal rule, no y/Y override available.
    let backend = TestBackend::new(120, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.advisory.pending_confirm = Some(crate::app::PendingConfirm {
        kind: crate::app::ConfirmKind::DestructiveVerb,
        tool: "shell:run".to_string(),
        target: "rm -rf .git".to_string(),
        rationale: None,
        allowlist: None,
        actor: Some("attacker".to_string()),
        remembered: false,
    });

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("REFUSED"));
    assert!(rendered.contains("destructive verb"));
    assert!(rendered.contains("rm -rf .git"));
    assert!(rendered.contains("always refused"));
    assert!(!rendered.contains("allow once"));
}

#[test]
fn confirm_keys_resolve_pending_confirm_with_remember_flag() {
    // y/Y/n/N drive `resolve_confirm`; verify the resolver clears
    // the gate and threads the `remembered` flag through.
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = ShellApp::new(V2Config::default(), None);
    app.advisory.pending_confirm = Some(crate::app::PendingConfirm {
        kind: crate::app::ConfirmKind::NetworkEgress,
        tool: "sandbox:run".to_string(),
        target: "curl x".to_string(),
        rationale: None,
        allowlist: None,
        actor: None,
        remembered: false,
    });
    app.handle_key(KeyEvent::new(KeyCode::Char('Y'), KeyModifiers::empty()));
    assert!(app.advisory.pending_confirm.is_none());
    // The system log line records the outcome.
    assert!(app
        .log
        .iter()
        .any(|line| line.body.contains("allowed") && line.body.contains("remembered")));
}

#[test]
fn agent_chat_renders_multi_turn_history_with_bubble_per_turn() {
    // `design/mockups/agent-chat.jsx::bubble` paints multi-turn
    // conversations as alternating you/agent bubbles.  Verify a
    // history of two prior turns + an active turn all reach the
    // buffer with their respective questions and answers visible.
    let backend = TestBackend::new(120, 36);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(
        V2Config {
            model: Some("openai:gpt-4.1".to_string()),
            ..V2Config::default()
        },
        None,
    );
    app.agent_chat = Some(crate::app::AgentChatView {
        question: "now what?".to_string(),
        answer: Some("scan first.".to_string()),
        running: false,
        abort_requested: false,
        error: None,
        history: vec![
            crate::app::ChatTurn {
                question: "what should I do first?".to_string(),
                answer: Some("build context.".to_string()),
                error: None,
            },
            crate::app::ChatTurn {
                question: "did context build succeed?".to_string(),
                answer: Some("yes, snapshot at .kuzushi/context-snapshot.json.".to_string()),
                error: None,
            },
        ],
        run_id: None,
        started_secs: 0,
        failure_context: None,
        pending_failure_context: None,
    });
    app.shell_view = ShellView::AgentChat;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    // History turn 1
    assert!(rendered.contains("what should I do first?"));
    assert!(rendered.contains("build context."));
    // History turn 2
    assert!(rendered.contains("did context build succeed?"));
    assert!(rendered.contains("snapshot at"));
    // Active turn
    assert!(rendered.contains("now what?"));
    assert!(rendered.contains("scan first."));
    // Both you/agent tags present at least once each.
    assert!(rendered.matches("you").count() >= 1);
    assert!(rendered.matches("agent").count() >= 1);
}

#[test]
fn agent_chat_fold_for_next_turn_pushes_completed_turn_into_history() {
    // Sanity-check the helper that backs the multi-turn UX: a
    // completed turn should fold into history; an empty initial
    // state should leave history empty.
    use crate::app::AgentChatView;

    let initial = AgentChatView::default();
    let next = initial.fold_for_next_turn("first question".to_string());
    assert!(next.history.is_empty());
    assert_eq!(next.question, "first question");

    let prev = AgentChatView {
        question: "first question".to_string(),
        answer: Some("first answer".to_string()),
        running: false,
        abort_requested: false,
        error: None,
        history: Vec::new(),
        run_id: None,
        started_secs: 0,
        failure_context: None,
        pending_failure_context: None,
    };
    let next2 = prev.fold_for_next_turn("second question".to_string());
    assert_eq!(next2.history.len(), 1);
    assert_eq!(next2.history[0].question, "first question");
    assert_eq!(next2.question, "second question");
}

#[test]
fn agent_chat_renders_role_tagged_bubbles() {
    // `design/mockups/agent-chat.jsx::bubble` paints a tag header on
    // each turn:  `  you  ──...──`  (c-accent) for the operator side,
    // ` agent ──...──` (c-success) for the agent side.  Verify both
    // tags reach the buffer when an agent question is in flight.
    let backend = TestBackend::new(120, 26);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(
        V2Config {
            model: Some("openai:gpt-4.1".to_string()),
            ..V2Config::default()
        },
        None,
    );
    app.agent_chat = Some(crate::app::AgentChatView {
        question: "What should I run first?".to_string(),
        answer: Some("Run sast:scan against the active target.".to_string()),
        running: false,
        abort_requested: false,
        error: None,
        history: Vec::new(),
        run_id: None,
        started_secs: 0,
        failure_context: None,
        pending_failure_context: None,
    });
    app.shell_view = ShellView::AgentChat;

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("you"), "missing operator tag: {rendered}");
    assert!(rendered.contains("agent"), "missing agent tag: {rendered}");
    assert!(rendered.contains("What should I run first?"));
    assert!(rendered.contains("Run sast:scan against the active target."));
}

#[test]
fn next_action_line_falls_back_to_primary_when_no_run_or_em_dash() {
    // Free-form NEXT hints (e.g. "Build the context snapshot with …")
    // should still render as warn glyph + primary body — no tool-name
    // accent, no muted suffix.
    let line = next_action_line(
        "Build the context snapshot with `context build` so SAST has structure to walk.",
        120,
    );
    assert!(line
        .spans
        .iter()
        .any(|s| s.style == theme::warn() && s.content.contains("▸ NEXT")));
    assert!(!line.spans.iter().any(|s| s.style == theme::accent()));
    assert!(!line.spans.iter().any(|s| s.style == theme::muted()));
}

#[test]
fn compact_finding_row_renders_alias_severity_and_location() {
    let line = compact_finding_row(
        "F-0001",
        "CRITICAL",
        SeverityTone::Critical,
        "sql injection via order_id concatenation",
        "apps/api/orders.rs:142",
        120,
    );
    let text = line_text(&line);
    assert!(text.contains("F-0001"));
    assert!(text.contains("CRITICAL"));
    assert!(text.contains("sql injection via order_id"));
    assert!(text.contains("apps/api/orders.rs:142"));
}

#[test]
fn error_notice_banner_renders_above_throttle() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Catalog;
    app.set_error_notice("tool", "semgrep:scan failed");
    app.set_throttle("anthropic", "429 retry-after 14s");

    let backend = TestBackend::new(120, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let buffer = terminal.backend().buffer();

    let error_row = banner_row(buffer, "ERROR").expect("ERROR chip present");
    let rate_row = banner_row(buffer, "RATE LIMIT").expect("RATE LIMIT chip present");
    assert!(error_row < rate_row, "error notice must sit above throttle");
}

#[test]
fn notice_banner_hidden_on_short_terminal() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Catalog;
    app.set_error_notice("tool", "boom");

    let backend = TestBackend::new(80, 4);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let buffer = terminal.backend().buffer();

    assert!(
        banner_row(buffer, "ERROR").is_none(),
        "notice banner must be suppressed under the 5-row floor"
    );
}

fn banner_row(buffer: &Buffer, needle: &str) -> Option<u16> {
    for y in 0..buffer.area.height {
        let mut row = String::new();
        for x in 0..buffer.area.width {
            row.push_str(buffer[(x, y)].symbol());
        }
        if row.contains(needle) {
            return Some(y);
        }
    }
    None
}

// ── Workbench command center ─────────────────────────────────────────────────

fn workbench_app_with_findings() -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Workbench;
    app.findings = vec![Finding::new_semgrep(
        "demo.sqli",
        "apps/api/orders.rs",
        12,
        Some(14),
        Severity::High,
        "sql injection via order_id",
    )];
    app
}

#[test]
fn workbench_renders_pane_borders_at_wide_and_narrow_widths() {
    for (width, height) in [(120, 24), (80, 30)] {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        let app = workbench_app_with_findings();

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("┌"), "no pane border at {width}x{height}");
        assert!(rendered.contains("SOURCE"), "no SOURCE at {width}x{height}");
        assert!(rendered.contains("CODE"), "no CODE at {width}x{height}");
        assert!(
            rendered.contains("FINDINGS"),
            "no FINDINGS at {width}x{height}"
        );
        assert!(
            rendered.contains("DETAILS"),
            "no DETAILS at {width}x{height}"
        );
        assert!(!rendered.contains("2/4 shown"), "{rendered}");
    }
}

#[test]
fn workbench_renders_three_column_intermediate_without_source() {
    let backend = TestBackend::new(110, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let app = workbench_app_with_findings();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("CODE"), "{rendered}");
    assert!(rendered.contains("FINDINGS"), "{rendered}");
    assert!(rendered.contains("DETAILS"), "{rendered}");
    assert!(!rendered.contains("SOURCE"), "{rendered}");
    assert!(!rendered.contains("2/4 shown"), "{rendered}");
}

#[test]
fn workbench_short_review_hint_names_real_constraints() {
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let app = workbench_app_with_findings();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("SOURCE+CODE/DFD hidden"), "{rendered}");
    assert!(rendered.contains(">=30 rows"), "{rendered}");
    assert!(rendered.contains(">=120 cols"), "{rendered}");
    assert!(rendered.contains("2/4 shown"), "{rendered}");
    assert!(rendered.contains("proof"), "{rendered}");
    assert!(rendered.contains("? unconfirmed"), "{rendered}");
    assert!(rendered.contains("FINDINGS"), "{rendered}");
    assert!(rendered.contains("DETAILS"), "{rendered}");
}

#[test]
fn workbench_top_bar_renders_journey_phase_rail_with_target() {
    let target = tempfile::tempdir().expect("temp target");
    let backend = TestBackend::new(140, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Workbench;
    app.target = Some(target.path().to_path_buf());

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("組 map"), "{rendered}");
    assert!(rendered.contains("崩 hunt"), "{rendered}");
    assert!(rendered.contains("作 confirm"), "{rendered}");
    assert!(rendered.contains("掛 fix"), "{rendered}");
}

#[test]
fn workbench_lines_plain_shows_top_bar_findings_and_dfd_empty_hint() {
    let app = workbench_app_with_findings();
    let rendered = render_plain_app(&app, 110);

    // Top bar identity, a findings row, and the cursor-following code/detail
    // preview. DFD is still available by focusing the center pane explicitly.
    assert!(rendered.contains("Kuzushi"), "{rendered}");
    assert!(
        rendered.contains("workspace export findings report.sarif"),
        "{rendered}"
    );
    assert!(rendered.contains("F-0001"), "{rendered}");
    assert!(
        rendered.contains("sql injection via order_id"),
        "{rendered}"
    );
    assert!(rendered.contains("CODE · F-0001"), "{rendered}");
    assert!(rendered.contains("source unavailable"), "{rendered}");
}

#[test]
fn workbench_selected_finding_gets_readable_details_pane() {
    let backend = TestBackend::new(180, 42);
    let mut terminal = Terminal::new(backend).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let source_path = temp.path().join("src/main/java/Demo.java");
    std::fs::create_dir_all(source_path.parent().unwrap()).unwrap();
    let source = (1..=50)
        .map(|line| {
            if line == 42 {
                "String sql = \"SELECT * FROM accounts WHERE id=\" + request.getParameter(\"id\");"
                    .to_string()
            } else {
                format!("// filler line {line}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&source_path, source).unwrap();
    let mut finding = Finding::new_semgrep(
        "demo.sqli",
        "src/main/java/Demo.java",
        42,
        Some(42),
        Severity::High,
        "Request parameter is concatenated into an SQL query string before prepareStatement(), so the prepared statement does not prevent SQL injection.",
    );
    finding.message = "The request parameter is attacker-controlled and is concatenated into the SQL text before prepareStatement is called.".to_string();
    finding.evidence = vec![FindingEvidence {
        kind: "source-sink".to_string(),
        file_path: finding.file_path.clone(),
        line: 42,
        snippet: "String sql = \"SELECT * FROM accounts WHERE id=\" + request.getParameter(\"id\");".to_string(),
        rationale: "Attacker-controlled source reaches SQL construction before the prepared statement boundary.".to_string(),
        confidence: 95,
        request_blob: None,
        response_blob: None,
    }];
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Workbench;
    app.workbench_focus = WorkbenchPane::Details;
    app.target = Some(temp.path().to_path_buf());
    app.findings = vec![finding.clone()];
    app.selected_finding = Some(finding);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("CODE"), "{rendered}");
    assert!(rendered.contains("Demo.java:42"), "{rendered}");
    assert!(rendered.contains("▶"), "{rendered}");
    assert!(rendered.contains("SELECT * FROM accounts"), "{rendered}");
    assert!(!rendered.contains("DFD"), "{rendered}");
    assert!(rendered.contains("DETAILS"), "{rendered}");
    assert!(
        rendered.contains("workspace export findings report.sarif"),
        "{rendered}"
    );
    assert!(rendered.contains("prepareStatement"), "{rendered}");
    assert!(rendered.contains("EVIDENCE"), "{rendered}");
    assert!(rendered.contains("source-sink"), "{rendered}");
    assert!(
        rendered.contains("Attacker-controlled source"),
        "{rendered}"
    );
}

#[test]
fn workbench_center_renders_dfd_title_when_artifact_present() {
    let temp = tempfile::tempdir().unwrap();
    let doc = serde_json::json!({
        "dfd": {
            "nodes": [
                {"id": "user", "name": "Browser", "trustZone": "internet"},
                {"id": "api", "name": "API server", "trustZone": "app-tier"}
            ],
            "flows": [
                {"id": "f1", "sourceId": "user", "targetId": "api", "description": "https"}
            ]
        }
    });
    let path = kuzushi_core::capabilities::persistent_threat_model_path(temp.path());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, serde_json::to_string(&doc).unwrap()).unwrap();

    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Workbench;
    app.target = Some(temp.path().to_path_buf());

    let rendered = render_plain_app(&app, 120);

    // The real data-flow diagram replaces the empty hint.
    assert!(rendered.contains("DATA-FLOW DIAGRAM"), "{rendered}");
    assert!(!rendered.contains("no threat model yet"), "{rendered}");
}
