use super::*;

#[test]
fn transcript_model_splits_multiline_log_entries() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.replace_log_for_test(vec![log_line("tool", "first\nsecond", 42)]);

    let model = transcript_model(&app, 10);

    assert_eq!(
        model.rows,
        vec![
            TranscriptRow {
                prefix: "tool".to_string(),
                body: "first".to_string(),
                continuation: false,
                time_secs: 42
            },
            TranscriptRow {
                prefix: "tool".to_string(),
                body: "second".to_string(),
                continuation: true,
                time_secs: 42
            }
        ]
    );
}

#[test]
fn transcript_model_tails_visible_rows_after_expansion() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.replace_log_for_test(vec![
        log_line("scan", "one", 1),
        log_line("agent", "two\nthree", 2),
    ]);

    let model = transcript_model(&app, 2);

    assert_eq!(
        model.rows,
        vec![
            TranscriptRow {
                prefix: "agent".to_string(),
                body: "two".to_string(),
                continuation: false,
                time_secs: 2
            },
            TranscriptRow {
                prefix: "agent".to_string(),
                body: "three".to_string(),
                continuation: true,
                time_secs: 2
            }
        ]
    );
}

#[test]
fn transcript_model_from_log_index_expands_entries_after_start() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.replace_log_for_test(vec![
        log_line("system", "before", 1),
        log_line("tool", "first\nsecond", 2),
    ]);

    let model = transcript_model_from_log_index(&app, 1);

    assert_eq!(
        model.rows,
        vec![
            TranscriptRow {
                prefix: "tool".to_string(),
                body: "first".to_string(),
                continuation: false,
                time_secs: 2
            },
            TranscriptRow {
                prefix: "tool".to_string(),
                body: "second".to_string(),
                continuation: true,
                time_secs: 2
            }
        ]
    );
}

#[test]
fn plain_command_result_model_formats_command_and_log_rows() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.replace_log_for_test(vec![
        log_line("old", "ignore", 1),
        log_line(">", "show me", 2),
        log_line("run", "first\nsecond", 3),
    ]);

    let model = plain_command_result_model(&app, "/run demo", 1);

    assert_eq!(model.result_title, "COMMAND RESULT");
    assert_eq!(model.view_title, "VIEW");
    assert_eq!(
        model.rows,
        vec![
            "command: /run demo".to_string(),
            "logs:".to_string(),
            "> show me".to_string(),
            "run: first".to_string(),
            "  second".to_string(),
        ]
    );
}

#[test]
fn transcript_model_keeps_empty_log_body_as_one_row() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.replace_log_for_test(vec![log_line("system", "", 0)]);

    let model = transcript_model(&app, 10);

    assert_eq!(
        model.rows,
        vec![TranscriptRow {
            prefix: "system".to_string(),
            body: String::new(),
            continuation: false,
            time_secs: 0
        }]
    );
}

#[test]
fn logs_model_shows_the_live_cache_when_nothing_aged_out() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.replace_log_for_test(vec![log_line("tool", "running", 1)]);

    let model = logs_model(&app);

    assert_eq!(bodies(&model), ["running"]);
    assert_eq!(model.summary, "1 log lines");
    assert_eq!(model.notice, None);
}

#[test]
fn logs_model_puts_recovered_history_ahead_of_the_live_cache() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.replace_log_for_test(vec![log_line("tool", "recent", 3)]);
    app.router.logs_mut().set_history(history(&[
        ("scan", "earliest"),
        ("scan", "earlier"),
        ("tool", "recent"),
    ]));

    let model = logs_model(&app);

    assert_eq!(bodies(&model), ["earliest", "earlier", "recent"]);
    assert_eq!(model.summary, "3 log lines · 2 from the session file");
}

#[test]
fn logs_model_filter_narrows_rows_and_reports_the_match_count() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.replace_log_for_test(vec![
        log_line("tool", "semgrep started", 1),
        log_line("error", "semgrep failed", 2),
        log_line("scan", "unrelated", 3),
    ]);
    app.router.logs_mut().push_filter_char('e');
    app.router.logs_mut().push_filter_char('r');
    app.router.logs_mut().push_filter_char('r');

    let model = logs_model(&app);

    assert_eq!(bodies(&model), ["semgrep failed"]);
    assert_eq!(model.summary, "1/3 log lines match \"err\"");
}

#[test]
fn logs_model_filter_matches_the_prefix_as_well_as_the_body() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.replace_log_for_test(vec![
        log_line("error", "disk full", 1),
        log_line("tool", "fine", 2),
    ]);
    for character in "error".chars() {
        app.router.logs_mut().push_filter_char(character);
    }

    assert_eq!(bodies(&logs_model(&app)), ["disk full"]);
}

#[test]
fn logs_model_says_so_when_a_filter_matches_nothing() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.replace_log_for_test(vec![log_line("tool", "running", 1)]);
    for character in "absent".chars() {
        app.router.logs_mut().push_filter_char(character);
    }

    let model = logs_model(&app);

    assert!(model.rows.is_empty());
    assert_eq!(
        model.notice.as_deref(),
        Some("no log lines match \"absent\" — Esc clears it")
    );
}

#[test]
fn logs_model_discloses_an_unreadable_transcript_rather_than_implying_a_gap() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.replace_log_for_test(vec![log_line("tool", "running", 1)]);
    app.router
        .logs_mut()
        .set_history(crate::app::log::session_history::SessionHistory::load(
            std::path::Path::new("/nonexistent/session.jsonl"),
        ));

    let notice = logs_model(&app).notice.unwrap_or_default();

    assert!(notice.starts_with("earlier lines unavailable:"), "{notice}");
}

fn bodies(model: &LogsModel) -> Vec<String> {
    model.rows.iter().map(|row| row.body.clone()).collect()
}

/// Builds a recovered history whose tail overlaps the live cache, the way a
/// real transcript does.
fn history(lines: &[(&str, &str)]) -> crate::app::log::session_history::SessionHistory {
    crate::app::log::session_history::SessionHistory::from_lines_for_test(
        lines
            .iter()
            .map(|(prefix, body)| log_line(prefix, body, 0))
            .collect(),
    )
}

fn log_line(prefix: &str, body: &str, time_secs: u64) -> LogLine {
    LogLine {
        prefix: prefix.to_string(),
        body: body.to_string(),
        time_secs,
    }
}
