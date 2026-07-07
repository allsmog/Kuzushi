use super::*;

#[test]
fn actor_detail_model_tails_visible_transcript_rows() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.replace_log_for_test(vec![
        log_line("scan", "started"),
        log_line("tool", "semgrep"),
        log_line("finding", "sql injection"),
    ]);

    let model = actor_detail_model(&app, 2);

    assert_eq!(model.status, "idle");
    assert_eq!(model.filter_label, "all");
    assert_eq!(
        model.transcript,
        vec![
            ActorTranscriptRow {
                prefix: "tool".to_string(),
                body: "semgrep".to_string()
            },
            ActorTranscriptRow {
                prefix: "finding".to_string(),
                body: "sql injection".to_string()
            }
        ]
    );
}

#[test]
fn actor_detail_model_applies_active_filter() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.router
        .actor_detail_mut()
        .set_filter(ActorDetailFilter::Errors);
    app.replace_log_for_test(vec![
        log_line("scan", "started"),
        log_line("error", "failed"),
    ]);

    let model = actor_detail_model(&app, 10);

    assert_eq!(model.filter_label, "errors");
    assert_eq!(
        model.transcript,
        vec![ActorTranscriptRow {
            prefix: "error".to_string(),
            body: "failed".to_string()
        }]
    );
}

fn log_line(prefix: &str, body: &str) -> LogLine {
    LogLine {
        prefix: prefix.to_string(),
        body: body.to_string(),
        time_secs: 0,
    }
}
