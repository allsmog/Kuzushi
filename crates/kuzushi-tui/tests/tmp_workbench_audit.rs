//! Temporary UI-audit probe: renders the Workbench at several sizes and dumps
//! the buffer so the audit can verify layout behavior. Delete after use.

use kuzushi_core::{Finding, FindingEvidence, Severity, V2Config};
use kuzushi_tui::{render_app, ShellApp, ShellView, WorkbenchPane};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

fn dump(width: u16, height: u16, app: &ShellApp) {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| render_app(frame, app)).unwrap();
    let buffer = terminal.backend().buffer();
    println!("==== {}x{} ====", width, height);
    for y in 0..height {
        let mut line = String::new();
        for x in 0..width {
            line.push_str(buffer[(x, y)].symbol());
        }
        println!("|{}|", line);
    }
}

fn sample_app(count: usize) -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.shell_view = ShellView::Workbench;
    app.workbench_focus = WorkbenchPane::Findings;
    app.findings = (0..count)
        .map(|index| {
            let mut finding = Finding::new_semgrep(
                format!("demo.rule.{index:04}"),
                "apps/api/very/long/nested/path/to/some/handler_module_file.rs",
                (index as u32) + 1,
                None,
                Severity::High,
                format!("record-{index:02} an intentionally long descriptive title that will need truncation"),
            );
            finding.fingerprint = format!("fp-{index:04}");
            finding.evidence = vec![FindingEvidence {
                kind: "supporting".to_string(),
                file_path: finding.file_path.clone(),
                line: 1,
                snippet: "let x = do_thing(input);".to_string(),
                rationale: "context".to_string(),
                confidence: 90,
                request_blob: None,
                response_blob: None,
            }];
            finding
        })
        .collect();
    app
}

#[test]
fn dump_workbench_80x24() {
    let app = sample_app(12);
    dump(80, 24, &app);
}

#[test]
fn dump_workbench_100x30() {
    let app = sample_app(12);
    dump(100, 30, &app);
}

#[test]
fn dump_workbench_140x40_selected() {
    let mut app = sample_app(12);
    app.selected_finding = Some(app.findings[0].clone());
    app.workbench_focus = WorkbenchPane::Details;
    dump(150, 40, &app);
}

#[test]
fn dump_workbench_details_after_g_bottom() {
    let mut app = sample_app(12);
    app.selected_finding = Some(app.findings[0].clone());
    app.workbench_focus = WorkbenchPane::Details;
    // Simulate `G` on the details pane: scroll_to_bottom sets u16::MAX.
    app.scroll_offset = u16::MAX;
    dump(150, 40, &app);
}
