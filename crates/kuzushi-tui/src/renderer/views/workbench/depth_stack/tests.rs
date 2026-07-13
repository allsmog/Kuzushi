use super::widgets::{cols, elide, fan_out, log_window, Elide, MORE};
use super::{render_workbench_depth, workbench_depth_lines};
use crate::app::{WorkbenchDepth, WorkbenchNav};
use crate::ui_view_models::{
    DrawerContent, FindingRow, LegKind, SeverityTone, Stanza, TraceLeg, Waypoint, WorkbenchModel,
};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

fn sample_findings() -> Vec<FindingRow> {
    vec![
        FindingRow {
            alias: "SQLI-014".to_string(),
            severity: SeverityTone::High,
            severity_label: "high".to_string(),
            title: "unsanitized query built from request".to_string(),
            location: "src/db.rs:42".to_string(),
            proof_label: "confirmed".to_string(),
            proof_marker: "◆",
            verdict: "true-positive".to_string(),
            confidence: "high".to_string(),
        },
        FindingRow {
            alias: "XSS-002".to_string(),
            severity: SeverityTone::Medium,
            severity_label: "medium".to_string(),
            title: "reflected xss in template".to_string(),
            location: "src/web.rs:9".to_string(),
            proof_label: "suspected".to_string(),
            proof_marker: "◔",
            verdict: "pending".to_string(),
            confidence: "medium".to_string(),
        },
    ]
}

fn sample_legs() -> Vec<TraceLeg> {
    vec![
        TraceLeg {
            index: 1,
            from: "req.body".to_string(),
            to: "build_query".to_string(),
            kind: LegKind::Source,
            meta: "src/web.rs:9".to_string(),
            waypoints: vec![Waypoint {
                label: "user input".to_string(),
                reached: true,
            }],
        },
        TraceLeg {
            index: 2,
            from: "build_query".to_string(),
            to: "db.exec".to_string(),
            kind: LegKind::Sink,
            meta: "src/db.rs:42".to_string(),
            waypoints: vec![],
        },
    ]
}

fn sample_drawer() -> DrawerContent {
    DrawerContent {
        triage: vec![Stanza {
            id: "verdict".to_string(),
            state: "true-positive".to_string(),
            state_tone: SeverityTone::High,
            summary: "confidence high".to_string(),
            body: "tainted request data reaches the query builder unescaped".to_string(),
        }],
        proof: vec![],
        log: vec!["semgrep: sql-injection rule matched".to_string()],
        code: vec!["db.exec(build_query(req.body))".to_string()],
    }
}

fn sample_model() -> WorkbenchModel {
    WorkbenchModel {
        findings: sample_findings(),
        has_selected_finding: true,
        selected: 0,
        flow_title: Some("CWE-89 · high".to_string()),
        legs: sample_legs(),
        drawer: sample_drawer(),
    }
}

fn render_to_string(nav: &WorkbenchNav, model: &WorkbenchModel) -> String {
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| render_workbench_depth(frame, frame.area(), nav, model))
        .unwrap();
    format!("{:?}", terminal.backend().buffer())
}

fn plain_text(nav: &WorkbenchNav, model: &WorkbenchModel) -> String {
    workbench_depth_lines(nav, model, 80)
        .iter()
        .flat_map(|line| line.spans.iter().map(|span| span.content.as_ref()))
        .collect::<Vec<_>>()
        .join("")
}

#[test]
fn list_depth_renders_findings_and_focus_map() {
    let rendered = render_to_string(&WorkbenchNav::default(), &sample_model());
    assert!(rendered.contains("FINDINGS"), "worklist title: {rendered}");
    assert!(rendered.contains("SQLI-014"));
    assert!(rendered.contains("findings")); // focus map / breadcrumb
}

#[test]
fn finding_depth_renders_the_focal_data_flow_ladder() {
    let nav = WorkbenchNav {
        depth: WorkbenchDepth::Finding,
        ..Default::default()
    };
    let rendered = render_to_string(&nav, &sample_model());
    assert!(rendered.contains("DATA-FLOW"), "ladder title: {rendered}");
    assert!(rendered.contains("DRAWER"));
    assert!(rendered.contains("db.exec") || rendered.contains("build_query"));
}

#[test]
fn plain_projection_shows_finding_depth_text() {
    let nav = WorkbenchNav {
        depth: WorkbenchDepth::Finding,
        ..Default::default()
    };
    let text = plain_text(&nav, &sample_model());
    assert!(text.contains("DATA-FLOW"), "plain ladder divider: {text}");
    assert!(text.contains("DRAWER · triage"));
    assert!(text.contains("db.exec") || text.contains("build_query"));
}

#[test]
fn empty_model_renders_guidance_not_a_panic() {
    let model = WorkbenchModel {
        findings: vec![],
        has_selected_finding: false,
        selected: 0,
        flow_title: None,
        legs: vec![],
        drawer: DrawerContent::default(),
    };
    let nav = WorkbenchNav {
        depth: WorkbenchDepth::Finding,
        ..Default::default()
    };
    let rendered = render_to_string(&nav, &model);
    assert!(rendered.contains("no data-flow"), "empty hint: {rendered}");
}

#[test]
fn prose_elision_marks_truncation_and_respects_the_budget() {
    let out = elide(
        "data-flow reaches an unsanitized SQL sink",
        Elide::Prose,
        20,
    );
    assert!(out.ends_with(MORE));
    assert!(cols(&out) <= 20);
}

#[test]
fn id_elision_keeps_head_and_tail() {
    let out = elide("SQLI-88213", Elide::Id, 8);
    assert!(out.starts_with("SQL"));
    assert!(out.ends_with("13"));
    assert!(cols(&out) <= 8);
}

#[test]
fn log_window_keeps_first_and_last_lines() {
    let lines: Vec<String> = (0..40).map(|index| format!("line {index}")).collect();
    let out = log_window(&lines, 5);
    assert_eq!(out.len(), 5);
    assert_eq!(out[0], "line 0");
    assert!(out[2].contains("36 lines"));
    assert_eq!(out[4], "line 39");
}

#[test]
fn fan_out_caps_and_counts_the_remainder() {
    let items = [1, 2, 3, 4, 5];
    let (shown, hidden) = fan_out(&items, 3);
    assert_eq!(shown, &[1, 2, 3]);
    assert_eq!(hidden, 2);
}
