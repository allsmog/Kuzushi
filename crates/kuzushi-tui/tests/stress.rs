//! M3 §3.2 — TUI stress test. Protects against transcript-buffer and
//! Findings-list regressions: pumping 10 000 log lines and rendering
//! 1 000 findings must stay bounded and never panic.
//!
//! Run with:
//!   cargo test -p kuzushi-tui --test stress -- --nocapture

use std::time::Instant;

use kuzushi_core::{Finding, FindingStore, Severity, V2Config};
use kuzushi_tui::{render_plain_app, ShellApp, ShellView};

const LARGE_LOG_LINES: usize = 10_000;
const LARGE_FINDING_COUNT: usize = 1_000;
const TRANSCRIPT_CAP: usize = 500;
const TRANSCRIPT_BUDGET_MS: u128 = 1_500;
const FINDINGS_RENDER_BUDGET_MS: u128 = 4_000;
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
    assert_eq!(app.log_len(), TRANSCRIPT_CAP);
    assert!(
        elapsed_ms < TRANSCRIPT_BUDGET_MS,
        "10k log calls took {elapsed_ms}ms (budget {TRANSCRIPT_BUDGET_MS}ms)"
    );
}

#[test]
fn logs_view_scroll_keys_clamp_safely_under_load() {
    // After saturating the buffer, j/k/g/G must clamp without panicking
    // even when the user pages past the visible region. Exact route-scroll
    // values are covered by the crate-local app tests; this integration
    // stress test protects the saturated transcript path.
    let mut app = ShellApp::new(V2Config::default(), None);
    for index in 0..LARGE_LOG_LINES {
        app.log("scan", format!("entry {index}"));
    }
    app.set_shell_view(ShellView::Logs);
    for _ in 0..50 {
        app.scroll_down(1);
    }
    app.scroll_to_bottom();
    for _ in 0..200 {
        app.scroll_up(1);
    }
    app.scroll_to_top();
    assert_eq!(app.log_len(), TRANSCRIPT_CAP);
    assert!(render_plain_app(&app, RENDER_WIDTH).contains("LOGS"));
}

#[test]
fn one_thousand_findings_render_findings_view_without_panic() {
    // Inserting and rendering 1 000 findings end-to-end protects the
    // Findings view's pagination + projection helpers against
    // accidental O(n²) walks or unwrap()s on edge cases. The write loop
    // is setup that exercises the event-sourced storage path; the timed
    // region covers the read + render round-trip the renderer owns, so
    // the budget tracks rendering cost rather than storage write
    // throughput.
    let store = FindingStore::open_in_memory().expect("in-memory store opens");
    store
        .record_run_started("stress-run", std::path::Path::new("/tmp"), "completed")
        .unwrap();
    let seeded_findings = (0..LARGE_FINDING_COUNT)
        .map(|index| {
            let severity = severity_cycle(index);
            Finding::new_tool(
                "stress",
                &format!("stress/rule-{index}"),
                "src/lib.rs",
                (index as u32) + 1,
                Some((index as u32) + 4),
                severity,
                &format!("stress entry {index}: arbitrary message body"),
            )
        })
        .collect::<Vec<_>>();
    store
        .insert_findings("stress-run", &seeded_findings)
        .expect("batch insert succeeds");
    let start = Instant::now();
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
    app.set_findings(findings);
    app.set_shell_view(ShellView::Workbench);

    let rendered = render_plain_app(&app, RENDER_WIDTH);
    let elapsed_ms = start.elapsed().as_millis();
    assert!(!rendered.is_empty(), "Workbench view must produce output");
    assert!(
        elapsed_ms < FINDINGS_RENDER_BUDGET_MS,
        "1k findings round-trip took {elapsed_ms}ms (budget {FINDINGS_RENDER_BUDGET_MS}ms)"
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
