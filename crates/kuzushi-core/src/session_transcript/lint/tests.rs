use super::*;
use serde_json::json;

fn record(sequence: u64, timestamp: &str, event_type: &str, payload: serde_json::Value) -> SessionRecord {
    SessionRecord {
        schema_version: 1,
        timestamp: timestamp.to_string(),
        session_id: "session".to_string(),
        sequence,
        event_id: format!("event-{sequence}"),
        parent_event_id: None,
        event_type: event_type.to_string(),
        payload,
    }
}

fn log(sequence: u64, timestamp: &str, message: &str) -> SessionRecord {
    record(
        sequence,
        timestamp,
        "log_emitted",
        json!({"level": "scope:mapping", "message": message}),
    )
}

fn stamp(minute: u64, second: u64) -> String {
    format!("2026-07-20T18:{minute:02}:{second:02}.000Z")
}

#[test]
fn timestamp_parsing_inverts_the_recorder_format() {
    let cases: &[(u64, &str)] = &[
        (0, "1970-01-01T00:00:00.000Z"),
        (1_709_164_800_123, "2024-02-29T00:00:00.123Z"),
        (1_784_571_691_540, "2026-07-20T18:21:31.540Z"),
    ];
    for (millis, formatted) in cases {
        assert_eq!(
            parse_timestamp_millis(formatted),
            Some(*millis),
            "parse {formatted}"
        );
    }
    assert_eq!(parse_timestamp_millis("not-a-timestamp"), None);
}

#[test]
fn repeated_message_inside_one_minute_is_a_storm() {
    let mut records: Vec<SessionRecord> = (0..30)
        .map(|i| log(i, &stamp(0, i), "project scopes ready: 124 nested scope(s)"))
        .collect();
    records.push(log(30, &stamp(0, 45), "one quiet unrelated line"));
    let findings = lint_session_records(&records, &SessionLintOptions::default());
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].kind, SessionLintKind::RepeatedMessageStorm);
    assert!(
        findings[0].detail.contains("project scopes ready")
            && findings[0].detail.contains("30 times"),
        "storm detail must name the message and its volume: {}",
        findings[0].detail
    );
}

#[test]
fn slow_paced_repeats_are_not_a_storm() {
    // The same line forty times, but one every two minutes — chatty,
    // not a storm; the per-minute peak never reaches the threshold.
    let records: Vec<SessionRecord> = (0..40)
        .map(|i| log(i, &format!("2026-07-20T{:02}:{:02}:00.000Z", (i * 2) / 60, (i * 2) % 60), "heartbeat"))
        .collect();
    let findings = lint_session_records(&records, &SessionLintOptions::default());
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn long_silence_after_a_view_change_is_flagged() {
    let records = vec![
        record(0, &stamp(0, 0), "view_changed", json!({"from": "Setup", "to": "Workbench"})),
        log(1, &stamp(2, 30), "eventually something happened"),
    ];
    let findings = lint_session_records(&records, &SessionLintOptions::default());
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].kind, SessionLintKind::SilentViewChange);
    assert!(
        findings[0].detail.contains("150s") && findings[0].detail.contains("Workbench"),
        "gap detail must carry the duration and destination view: {}",
        findings[0].detail
    );
}

#[test]
fn view_change_followed_by_prompt_activity_or_session_end_is_clean() {
    let answered = vec![
        record(0, &stamp(0, 0), "view_changed", json!({"to": "Workbench"})),
        log(1, &stamp(0, 1), "workbench hydrated"),
    ];
    let quit = vec![
        record(0, &stamp(0, 0), "view_changed", json!({"to": "Workbench"})),
        record(1, &stamp(9, 0), "session_end", json!({"reason": "quit"})),
    ];
    let options = SessionLintOptions::default();
    assert!(lint_session_records(&answered, &options).is_empty());
    assert!(lint_session_records(&quit, &options).is_empty());
}

#[test]
fn slow_first_response_names_the_command_and_the_gap() {
    let records = vec![
        record(0, &stamp(0, 0), "command_submitted", json!({"command": "workbench"})),
        log(1, &stamp(0, 12), "opened workbench"),
    ];
    let findings = lint_session_records(&records, &SessionLintOptions::default());
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].kind, SessionLintKind::SlowFirstResponse);
    assert!(
        findings[0].detail.contains("workbench") && findings[0].detail.contains("12.0s"),
        "latency detail must carry the command and the measured gap: {}",
        findings[0].detail
    );
}

#[test]
fn prompt_command_with_a_fast_response_is_clean() {
    let records = vec![
        record(0, &stamp(0, 0), "command_submitted", json!({"command": "help"})),
        log(1, &stamp(0, 1), "showing help"),
    ];
    let findings = lint_session_records(&records, &SessionLintOptions::default());
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn command_with_no_recorded_response_is_flagged() {
    let records = vec![record(
        0,
        &stamp(0, 0),
        "command_submitted",
        json!({"command": "scan"}),
    )];
    let findings = lint_session_records(&records, &SessionLintOptions::default());
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(
        findings[0].detail.contains("no response was ever recorded"),
        "{}",
        findings[0].detail
    );
}
