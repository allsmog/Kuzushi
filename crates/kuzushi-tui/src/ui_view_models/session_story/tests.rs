use super::*;
use std::path::PathBuf;

#[test]
fn session_history_model_tails_commands_with_original_numbers() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_command_history((1..=60).map(|number| format!("cmd-{number}")).collect());

    let model = session_history_model(&app, 50);

    assert_eq!(model.number_width, 2);
    assert_eq!(model.rows.len(), 50);
    assert_eq!(
        model.rows.first(),
        Some(&CommandHistoryRow {
            cells: ["11".to_string(), "cmd-11".to_string()]
        })
    );
    assert_eq!(
        model.rows.last(),
        Some(&CommandHistoryRow {
            cells: ["60".to_string(), "cmd-60".to_string()]
        })
    );
}

#[test]
fn session_story_model_filters_prompt_echoes_and_tails_events() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.replace_log_for_test(vec![
        log_line(">", "scan ."),
        log_line("scan", "started"),
        log_line("tool", "semgrep"),
        log_line("finding", "sql injection"),
    ]);

    let model = session_story_model(&app, 2);

    assert_eq!(
        model.events,
        vec![
            SessionStoryRow {
                cells: ["tool".to_string(), "semgrep".to_string()]
            },
            SessionStoryRow {
                cells: ["finding".to_string(), "sql injection".to_string()]
            }
        ]
    );
}

#[test]
fn scan_story_row_describes_running_scan_state() {
    let scan = ScanPanelState {
        run_id: Some("run-1".to_string()),
        target: PathBuf::from("/tmp/demo"),
        stage: "verify".to_string(),
        findings_count: 3,
        running: true,
        abort_requested: false,
        error: None,
    };

    assert_eq!(
        scan_story_row(&scan, true),
        SessionStoryRow {
            cells: [
                "scan".to_string(),
                "paused · stage=verify · findings=3".to_string()
            ]
        }
    );
}

fn log_line(prefix: &str, body: &str) -> LogLine {
    LogLine {
        prefix: prefix.to_string(),
        body: body.to_string(),
        time_secs: 0,
    }
}
