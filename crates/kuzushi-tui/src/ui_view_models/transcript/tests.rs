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

fn log_line(prefix: &str, body: &str, time_secs: u64) -> LogLine {
    LogLine {
        prefix: prefix.to_string(),
        body: body.to_string(),
        time_secs,
    }
}
