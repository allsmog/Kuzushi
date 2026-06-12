//! M3 §3.2 — TUI stress test. Protects against transcript-buffer and
//! Findings-list regressions: pumping 10 000 log lines and rendering
//! 1 000 findings must stay well under the second and never panic.
//!
//! Run with:
//!   cargo test -p kuzushi-tui --test stress -- --nocapture

use std::time::Instant;

use kuzushi_core::{Finding, FindingStore, Severity, V2Config};
use kuzushi_tui::{render_plain_app, ShellApp, ShellView};

const LARGE_LOG_LINES: usize = 10_000;
const LARGE_FINDING_COUNT: usize = 1_000;
const TRANSCRIPT_CAP: usize = 500;
const STRESS_BUDGET_MS: u128 = 1_500;
const RENDER_WIDTH: usize = 120;

#[test]
fn ten_thousand_log_calls_stay_inside_the_500_line_cap_without_panicking() {
    // Production transcripts are capped at 500 lines (see
    // `ShellApp::log` in `shell_lifecycle/log_and_scroll.rs`). Pumping
    // 20× the cap exercises the eviction path repeatedly. The cap is a
    // load-bearing guard against unbounded memory growth when a scan
    // emits thousands of log lines, so this regression locks the cap
    // in alongside its performance budget.
    let start = Instant::now();
    let mut app = ShellApp::new(V2Config::default(), None);
    for index in 0..LARGE_LOG_LINES {
        app.log(
            "scan",
            format!("synthetic entry {index}: large transcript stress"),
        );
    }
    let elapsed_ms = start.elapsed().as_millis();
    assert_eq!(app.log.len(), TRANSCRIPT_CAP);
    assert!(
        elapsed_ms < STRESS_BUDGET_MS,
        "10k log calls took {elapsed_ms}ms (budget {STRESS_BUDGET_MS}ms)"
    );
}

#[test]
fn logs_view_scroll_keys_clamp_safely_under_load() {
    // After saturating the buffer, j/k/g/G must clamp without panicking
    // even when the user pages past the visible region. This protects
    // the Logs view (M1 §1.1) against an off-by-one in
    // `scroll_down`/`scroll_to_bottom` when usize::MAX is used as a
    // sentinel.
    let mut app = ShellApp::new(V2Config::default(), None);
    for index in 0..LARGE_LOG_LINES {
        app.log("scan", format!("entry {index}"));
    }
    app.shell_view = ShellView::Logs;
    for _ in 0..50 {
        app.scroll_down(1);
    }
    let mid_scroll = app.logs_scroll;
    app.scroll_to_bottom();
    assert!(app.logs_scroll >= mid_scroll, "G must not regress scroll");
    for _ in 0..200 {
        app.scroll_up(1);
    }
    app.scroll_to_top();
    assert_eq!(app.logs_scroll, 0);
}

#[test]
fn one_thousand_findings_render_findings_view_without_panic() {
    // Inserting and rendering 1 000 findings end-to-end protects the
    // Findings view's pagination + projection helpers against
    // accidental O(n²) walks or unwrap()s on edge cases. Time budget is
    // looser than the log test because rendering touches the renderer.
    let start = Instant::now();
    let store = FindingStore::open_in_memory().expect("in-memory store opens");
    store
        .insert_scan_run("stress-run", std::path::Path::new("/tmp"), "completed")
        .unwrap();
    for index in 0..LARGE_FINDING_COUNT {
        let severity = severity_cycle(index);
        let finding = Finding::new_tool(
            "stress",
            &format!("stress/rule-{index}"),
            "src/lib.rs",
            (index as u32) + 1,
            Some((index as u32) + 4),
            severity,
            &format!("stress entry {index}: arbitrary message body"),
        );
        store
            .insert_finding("stress-run", &finding)
            .expect("insert succeeds");
    }
    let findings = store
        .list_findings(LARGE_FINDING_COUNT)
        .expect("list succeeds");
    // The store caps `list_findings(...)` at FindingListFilter::MAX_LIMIT
    // (500) — the stress test inserts more to exercise the write path,
    // then renders the capped read so the renderer sees the largest
    // realistic working set.
    assert!(
        !findings.is_empty(),
        "list_findings should return up to MAX_LIMIT rows"
    );
    assert!(
        findings.len() <= LARGE_FINDING_COUNT,
        "list must not exceed requested limit"
    );
    let mut app = ShellApp::new(V2Config::default(), None);
    app.findings = findings;
    app.shell_view = ShellView::Findings;

    let rendered = render_plain_app(&app, RENDER_WIDTH);
    let elapsed_ms = start.elapsed().as_millis();
    assert!(!rendered.is_empty(), "Findings view must produce output");
    assert!(
        elapsed_ms < STRESS_BUDGET_MS,
        "1k findings round-trip took {elapsed_ms}ms (budget {STRESS_BUDGET_MS}ms)"
    );
}

fn severity_cycle(index: usize) -> Severity {
    const CYCLE: [Severity; 5] = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];
    CYCLE[index % CYCLE.len()]
}
