use super::*;

#[test]
fn shell_app_records_semantic_boundaries_and_terminal_state() {
    let temp = tempfile::tempdir().unwrap();
    let store = SessionTranscriptStore::from_root(temp.path().join("sessions"));
    let (mut app, session_id) = transcript_test_app(&store, temp.path());
    record_test_session_events(&mut app, temp.path());

    let read = store.read(&session_id).unwrap();
    assert_test_session_events(&read);
}

#[test]
fn run_turn_and_answer_events_cross_a_flush_barrier() {
    let temp = tempfile::tempdir().unwrap();
    let store = SessionTranscriptStore::from_root(temp.path().join("sessions"));
    let recorder = store
        .start(SessionMetadata::new("scripted", temp.path()))
        .unwrap();
    let transcript = ShellSessionTranscript::new(recorder.clone());

    for (sequence, event) in [
        (
            1,
            SessionEvent::RunStarted {
                run_id: "run-1".to_string(),
                tool_name: "test:run".to_string(),
            },
        ),
        (
            2,
            SessionEvent::AgentUserTurn {
                text: "inspect this".to_string(),
            },
        ),
        (
            3,
            SessionEvent::OperatorAnswer {
                question_id: "q-1".to_string(),
                kind: "operator".to_string(),
                outcome: "submitted".to_string(),
                answer: Some("approved".to_string()),
            },
        ),
    ] {
        transcript.record(event).unwrap();
        assert_eq!(recorder.status().last_flushed_sequence, sequence);
    }

    recorder.shutdown("completed").unwrap();
}

#[test]
fn plan_and_threat_failure_logs_never_transcribe_raw_model_content() {
    let temp = tempfile::tempdir().unwrap();
    let store = SessionTranscriptStore::from_root(temp.path().join("sessions"));
    let (mut app, session_id) = transcript_test_app(&store, temp.path());
    let raw_failure = "invalid response body RAW_WORKER_RESPONSE_SENTINEL";

    app.apply_plan_event(PlanEvent::Failed {
        error: raw_failure.to_string(),
        audit: AgentCallAudit::test(),
    });
    app.apply_threat_patch_event(ThreatPatchEvent::Failed {
        error: raw_failure.to_string(),
        audit: AgentCallAudit::test(),
    });

    assert!(app
        .log_lines()
        .iter()
        .all(|line| !line.body.contains("RAW_WORKER_RESPONSE_SENTINEL")));
    assert!(app.log_lines().iter().any(|line| {
        line.body
            .contains("planner failed: model request failed (invalid_response)")
    }));
    assert!(app.log_lines().iter().any(|line| {
        line.body
            .contains("threats worker failed: model request failed (invalid_response)")
    }));

    app.finish_session_transcript("completed");
    let transcript = store.read(&session_id).unwrap();
    assert!(!transcript
        .raw_jsonl
        .contains("RAW_WORKER_RESPONSE_SENTINEL"));
    assert_eq!(
        transcript
            .records
            .iter()
            .filter(|record| record.event_type == "log_emitted")
            .filter(|record| {
                record.payload["message"]
                    .as_str()
                    .is_some_and(|message| message.contains("model request failed"))
            })
            .count(),
        2
    );
}

#[test]
fn runtime_diagnostics_stay_in_memory_instead_of_entering_the_transcript() {
    let temp = tempfile::tempdir().unwrap();
    let store = SessionTranscriptStore::from_root(temp.path().join("sessions"));
    let (mut app, session_id) = transcript_test_app(&store, temp.path());

    app.log_ephemeral("kwp:stderr", "OPAQUE_CHILD_SECRET");
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.body.contains("OPAQUE_CHILD_SECRET")));
    app.finish_session_transcript("completed");

    let transcript = store.read(&session_id).unwrap();
    assert!(!transcript.raw_jsonl.contains("OPAQUE_CHILD_SECRET"));
}

fn transcript_test_app(
    store: &SessionTranscriptStore,
    root: &std::path::Path,
) -> (ShellApp, String) {
    let mut metadata = SessionMetadata::new("scripted", root);
    metadata.argv = vec!["--plain".to_string()];
    metadata.target_source = Some("none".to_string());
    let recorder = store.start(metadata).unwrap();
    let session_id = recorder.session_id().to_string();
    let app = ShellApp::with_registry_and_transcript(
        V2Config::default(),
        None,
        ModuleRegistry::with_v2_builtins(),
        Some(recorder),
    );
    (app, session_id)
}

fn record_test_session_events(app: &mut ShellApp, root: &std::path::Path) {
    let target = root.join("target");
    std::fs::create_dir(&target).unwrap();
    app.reduce_submitted_line("help");
    app.set_shell_view(ShellView::Help);
    app.set_target(Some(target));
    app.record_session_event(SessionEvent::RunStarted {
        run_id: "run-1".to_string(),
        tool_name: "test:run".to_string(),
    });
    app.record_session_event(SessionEvent::OperatorAnswer {
        question_id: "q-1".to_string(),
        kind: "operator".to_string(),
        outcome: "submitted".to_string(),
        answer: Some("approved".to_string()),
    });
    app.record_session_event(SessionEvent::RunFinished {
        run_id: "run-1".to_string(),
        tool_name: "test:run".to_string(),
        status: "completed".to_string(),
    });
    app.set_target(None);
    app.finish_session_transcript("completed");
}

fn assert_test_session_events(read: &kuzushi_core::session_transcript::SessionReadResult) {
    let event_types = read
        .records
        .iter()
        .map(|record| record.event_type.as_str())
        .collect::<Vec<_>>();
    for expected in [
        "session_meta",
        "command_submitted",
        "view_changed",
        "target_activated",
        "run_started",
        "operator_answer",
        "run_finished",
        "target_cleared",
        "session_end",
    ] {
        assert!(
            event_types.contains(&expected),
            "missing {expected}: {event_types:?}"
        );
    }
    assert_eq!(read.summary.current_target, None);
    assert_eq!(
        read.summary.status,
        kuzushi_core::session_transcript::SessionStatus::Completed
    );
}

#[test]
fn transcript_start_failure_warning_stays_visible_and_in_session_status() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.surface_session_start_warning("permission denied; Kuzushi will continue".to_string());
    let notice_time = app.advisory().notice.as_ref().unwrap().since;

    assert!(!app.tick_at(notice_time + std::time::Duration::from_secs(3_600)));
    assert_eq!(app.advisory().notice.as_ref().unwrap().source, "session");
    app.show_session_transcript_status();
    assert!(app.log_lines().iter().any(|line| line
        .body
        .contains("recording unavailable: permission denied")));
}
