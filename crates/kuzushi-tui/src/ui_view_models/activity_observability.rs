use super::activity_header::ActivityRunOutcome;
use crate::{ActivitySession, DagTaskState};
use std::time::{Duration, Instant};

pub(crate) const ACTIVITY_STALE_PROGRESS_AFTER: Duration = Duration::from_secs(30);
/// A model call is quiet by nature; only past this age does an open call
/// escalate to the stall banners instead of "query in flight".
pub(crate) const MODEL_CALL_WATCHDOG: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActivityHeartbeatTone {
    Live,
    Stalled,
    Complete,
    Warning,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityHeartbeatModel {
    pub(crate) text: String,
    pub(crate) tone: ActivityHeartbeatTone,
}

pub(crate) fn activity_heartbeat_model(
    session: &ActivitySession,
    running_tool: Option<&str>,
    live: bool,
    outcome: Option<&ActivityRunOutcome>,
    now: Instant,
) -> ActivityHeartbeatModel {
    if matches!(outcome, Some(ActivityRunOutcome::WaitingForOperator)) {
        return ActivityHeartbeatModel {
            text: " ? WAITING INPUT · operator answer required · run paused safely".to_string(),
            tone: ActivityHeartbeatTone::Warning,
        };
    }
    let (age, source) = progress_signal(session, now);
    if !live {
        return finished_heartbeat(age, &source, outcome);
    }
    if age >= ACTIVITY_STALE_PROGRESS_AFTER {
        return stale_heartbeat(session, running_tool, now, age, &source);
    }
    ActivityHeartbeatModel {
        text: format!(
            " ● LIVE · current {} · last progress {} ago · {source}",
            current_subject(session, running_tool),
            age_label(age),
        ),
        tone: ActivityHeartbeatTone::Live,
    }
}

/// A stale progress signal with an in-flight model call under the watchdog
/// is honest quiet work, not a stall; only past the watchdog does the
/// NO PROGRESS banner fire.
fn stale_heartbeat(
    session: &ActivitySession,
    running_tool: Option<&str>,
    now: Instant,
    age: Duration,
    source: &str,
) -> ActivityHeartbeatModel {
    if let Some(query_age) = open_query_in_flight(session, now) {
        return ActivityHeartbeatModel {
            text: format!(
                " ◐ query in flight {} · current {} · last {source}",
                age_label(query_age),
                current_subject(session, running_tool),
            ),
            tone: ActivityHeartbeatTone::Live,
        };
    }
    ActivityHeartbeatModel {
        text: format!(
            " ⚠ NO PROGRESS SIGNAL for {} · current {} · last {source} · Ctrl+C cancels",
            age_label(age),
            current_subject(session, running_tool),
        ),
        tone: ActivityHeartbeatTone::Stalled,
    }
}

fn finished_heartbeat(
    age: Duration,
    source: &str,
    outcome: Option<&ActivityRunOutcome>,
) -> ActivityHeartbeatModel {
    let terminal = terminal_heartbeat(outcome);
    ActivityHeartbeatModel {
        text: format!(
            " {} · last signal {} ago · {source}",
            terminal.label,
            age_label(age)
        ),
        tone: terminal.tone,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TerminalHeartbeat {
    label: &'static str,
    tone: ActivityHeartbeatTone,
}

fn terminal_heartbeat(outcome: Option<&ActivityRunOutcome>) -> TerminalHeartbeat {
    let status = match outcome {
        Some(ActivityRunOutcome::WaitingForOperator) => "waiting",
        Some(ActivityRunOutcome::Failed { .. }) => "failed",
        Some(ActivityRunOutcome::Terminal { status, .. }) => status.as_str(),
        None => "completed",
    };
    match status {
        "blocked" => terminal("▣ BLOCKED", ActivityHeartbeatTone::Warning),
        "failed" | "refused" | "interrupted" => terminal("✗ FAILED", ActivityHeartbeatTone::Failed),
        "partial" => terminal("⚠ PARTIAL", ActivityHeartbeatTone::Warning),
        "canceled" | "cancelled" => terminal("× CANCELED", ActivityHeartbeatTone::Warning),
        "skipped" => terminal("⊘ SKIPPED", ActivityHeartbeatTone::Warning),
        _ => terminal("✓ COMPLETE", ActivityHeartbeatTone::Complete),
    }
}

fn terminal(label: &'static str, tone: ActivityHeartbeatTone) -> TerminalHeartbeat {
    TerminalHeartbeat { label, tone }
}

fn current_subject(session: &ActivitySession, running_tool: Option<&str>) -> String {
    running_tool
        .map(str::to_string)
        .or_else(|| active_task(session).map(|task| task.operator_name().to_string()))
        .unwrap_or_else(|| "run finalization".to_string())
}

fn active_task(session: &ActivitySession) -> Option<&crate::DagTaskRow> {
    session
        .tasks
        .values()
        .find(|task| matches!(task.state, DagTaskState::Active | DagTaskState::Canceling))
}

/// The age of an open model call still under the watchdog, if one exists.
pub(crate) fn open_query_in_flight(session: &ActivitySession, now: Instant) -> Option<Duration> {
    session
        .open_model_call_age(now)
        .filter(|age| *age < MODEL_CALL_WATCHDOG)
}

fn progress_signal(session: &ActivitySession, now: Instant) -> (Duration, String) {
    let observed_at = session.last_run_item_at().unwrap_or(session.started_at);
    let presentation = kuzushi_core::run_lifecycle::present_projection_with_hydration_and_health(
        &session.run_projection,
        kuzushi_core::run_lifecycle::RunProjectionSource::TypedV1,
        &session.run_presentation_hydration,
        session.effective_run_lifecycle_health(),
    );
    let label = presentation
        .timeline_text_rows()
        .last()
        .map(|row| row.text.clone())
        .unwrap_or_else(|| "run started".to_string());
    (
        now.checked_duration_since(observed_at).unwrap_or_default(),
        label,
    )
}

fn age_label(age: Duration) -> String {
    let seconds = age.as_secs();
    if seconds < 60 {
        return format!("{seconds}s");
    }
    format!("{}m{:02}s", seconds / 60, seconds % 60)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::run_lifecycle::{
        ModelUsage, OperationFingerprint, RunCallId, RunId, RunItemEnvelopeV1, RunItemId,
        RunItemSource, RunItemStatus, RunItemV1, SafeText,
    };
    use kuzushi_core::WorkflowPhase;

    fn model_call_started(
        session: &ActivitySession,
        seq: u64,
        item_id: RunItemId,
        call_id: RunCallId,
    ) -> RunItemEnvelopeV1 {
        RunItemEnvelopeV1::new(
            seq,
            RunId::parse(&session.run_id).unwrap(),
            item_id,
            RunItemSource::Runtime,
            RunItemV1::ModelCallStarted {
                provider: SafeText::operator_visible("anthropic"),
                model: SafeText::operator_visible("claude"),
                operation_fingerprint: OperationFingerprint::from_bytes(b"model call"),
            },
            session.run_projection.last_event_hash.clone(),
        )
        .unwrap()
        .with_call(call_id)
        .unwrap()
    }

    fn model_call_finished(
        session: &ActivitySession,
        seq: u64,
        item_id: RunItemId,
        call_id: RunCallId,
        latency_ms: u64,
    ) -> RunItemEnvelopeV1 {
        RunItemEnvelopeV1::new(
            seq,
            RunId::parse(&session.run_id).unwrap(),
            item_id,
            RunItemSource::Runtime,
            RunItemV1::ModelCallFinished {
                provider: SafeText::operator_visible("anthropic"),
                model: SafeText::operator_visible("claude"),
                status: RunItemStatus::Completed,
                latency_ms,
                usage: ModelUsage {
                    input_tokens: None,
                    output_tokens: None,
                },
                cost: kuzushi_core::runtime::RuntimeCostReport::known(
                    kuzushi_core::runtime::RuntimeCost::ZERO,
                ),
                error_class: None,
            },
            session.run_projection.last_event_hash.clone(),
        )
        .unwrap()
        .with_call(call_id)
        .unwrap()
    }

    fn assert_query_in_flight(session: &ActivitySession, probe: Instant, expected_age: Duration) {
        assert_eq!(session.open_model_call_age(probe), Some(expected_age));
        let heartbeat =
            activity_heartbeat_model(session, Some("threat-model:build"), true, None, probe);
        assert_eq!(
            heartbeat.tone,
            ActivityHeartbeatTone::Live,
            "{}",
            heartbeat.text
        );
        assert!(
            heartbeat
                .text
                .contains(&format!("query in flight {}", age_label(expected_age))),
            "{}",
            heartbeat.text
        );
        assert!(
            !heartbeat.text.contains("NO PROGRESS SIGNAL"),
            "{}",
            heartbeat.text
        );
    }

    fn assert_watchdog_stalled(session: &ActivitySession, probe: Instant) {
        let heartbeat =
            activity_heartbeat_model(session, Some("threat-model:build"), true, None, probe);
        assert_eq!(heartbeat.tone, ActivityHeartbeatTone::Stalled);
        assert!(
            heartbeat.text.contains("NO PROGRESS SIGNAL"),
            "{}",
            heartbeat.text
        );
    }

    #[test]
    fn stale_live_activity_names_the_current_tool_and_last_real_signal() {
        let now = Instant::now();
        let mut session = ActivitySession::for_phase("context-run", WorkflowPhase::Map);
        session
            .apply_run_item(
                kuzushi_core::run_lifecycle::RunItemEnvelopeV1::new(
                    1,
                    kuzushi_core::run_lifecycle::RunId::parse("context-run").unwrap(),
                    kuzushi_core::run_lifecycle::RunItemId::new(),
                    kuzushi_core::run_lifecycle::RunItemSource::Workflow,
                    kuzushi_core::run_lifecycle::RunItemV1::DiagnosticNotice {
                        level: kuzushi_core::run_lifecycle::DiagnosticLevel::Info,
                        message: kuzushi_core::run_lifecycle::SafeText::operator_visible(
                            "Building repository inventory",
                        ),
                    },
                    None,
                )
                .unwrap(),
            )
            .unwrap();
        session.set_last_run_item_at_for_test(now - Duration::from_secs(45));

        let model = activity_heartbeat_model(&session, Some("context:build"), true, None, now);

        assert_eq!(model.tone, ActivityHeartbeatTone::Stalled);
        assert!(
            model.text.contains("NO PROGRESS SIGNAL for 45s"),
            "{}",
            model.text
        );
        assert!(
            model.text.contains("current context:build"),
            "{}",
            model.text
        );
        assert!(
            model.text.contains("Building repository inventory"),
            "{}",
            model.text
        );
    }

    /// C1: a quiet-but-open model call under the watchdog reads as work in
    /// flight, not a stall; past the watchdog it escalates like any stall.
    #[test]
    fn open_model_call_reports_query_in_flight_instead_of_a_false_stall() {
        let mut session = ActivitySession::for_phase("model-run", WorkflowPhase::Scan);
        let observed_at = Instant::now();
        let start = model_call_started(&session, 1, RunItemId::new(), RunCallId::new());
        session
            .apply_run_item_at_for_test(start, observed_at)
            .unwrap();

        assert_query_in_flight(
            &session,
            observed_at + Duration::from_secs(45),
            Duration::from_secs(45),
        );
        assert_watchdog_stalled(&session, observed_at + Duration::from_secs(400));
    }

    #[test]
    fn overlapping_model_calls_use_the_remaining_calls_own_watchdog_age() {
        let mut session = ActivitySession::for_phase("overlap-run", WorkflowPhase::Scan);
        let observed_at = Instant::now();
        let first_call = RunCallId::new();
        let second_call = RunCallId::new();
        let first_item = RunItemId::new();
        let second_item = RunItemId::new();

        let first_start = model_call_started(&session, 1, first_item, first_call);
        session
            .apply_run_item_at_for_test(first_start, observed_at)
            .unwrap();
        let second_start = model_call_started(&session, 2, second_item, second_call);
        session
            .apply_run_item_at_for_test(second_start, observed_at + Duration::from_secs(290))
            .unwrap();
        let first_finish = model_call_finished(&session, 3, first_item, first_call, 295_000);
        session
            .apply_run_item_at_for_test(first_finish, observed_at + Duration::from_secs(295))
            .unwrap();

        assert_query_in_flight(
            &session,
            observed_at + Duration::from_secs(326),
            Duration::from_secs(36),
        );
        assert_watchdog_stalled(&session, observed_at + Duration::from_secs(591));
    }

    #[test]
    fn duplicate_model_start_preserves_the_original_watchdog_clock() {
        let mut session = ActivitySession::for_phase("duplicate-start", WorkflowPhase::Scan);
        let observed_at = Instant::now();
        let start = model_call_started(&session, 1, RunItemId::new(), RunCallId::new());
        session
            .apply_run_item_at_for_test(start.clone(), observed_at)
            .unwrap();
        session
            .apply_run_item_at_for_test(start, observed_at + Duration::from_secs(200))
            .unwrap();

        assert_query_in_flight(
            &session,
            observed_at + Duration::from_secs(250),
            Duration::from_secs(250),
        );
        assert_watchdog_stalled(&session, observed_at + Duration::from_secs(301));
    }

    #[test]
    fn duplicate_model_finish_does_not_close_another_open_call() {
        let mut session = ActivitySession::for_phase("duplicate-finish", WorkflowPhase::Scan);
        let observed_at = Instant::now();
        let first_call = RunCallId::new();
        let second_call = RunCallId::new();
        let first_item = RunItemId::new();
        let first_start = model_call_started(&session, 1, first_item, first_call);
        session
            .apply_run_item_at_for_test(first_start, observed_at)
            .unwrap();
        let second_start = model_call_started(&session, 2, RunItemId::new(), second_call);
        session
            .apply_run_item_at_for_test(second_start, observed_at + Duration::from_secs(10))
            .unwrap();
        let first_finish = model_call_finished(&session, 3, first_item, first_call, 20_000);
        session
            .apply_run_item_at_for_test(first_finish.clone(), observed_at + Duration::from_secs(20))
            .unwrap();
        session
            .apply_run_item_at_for_test(first_finish, observed_at + Duration::from_secs(30))
            .unwrap();

        assert_query_in_flight(
            &session,
            observed_at + Duration::from_secs(70),
            Duration::from_secs(60),
        );
    }

    #[test]
    fn failed_terminal_activity_never_uses_a_success_heartbeat() {
        let now = Instant::now();
        let session = ActivitySession::for_phase("failed-run", WorkflowPhase::Map);
        let outcome = ActivityRunOutcome::Terminal {
            status: "failed".to_string(),
            findings: None,
            reason: Some("context snapshot was too large".to_string()),
        };

        let model = activity_heartbeat_model(&session, None, false, Some(&outcome), now);

        assert_eq!(model.tone, ActivityHeartbeatTone::Failed);
        assert!(model.text.contains("✗ FAILED"), "{}", model.text);
        assert!(!model.text.contains("✓ COMPLETE"), "{}", model.text);
    }

    #[test]
    fn blocked_terminal_activity_uses_a_warning_heartbeat() {
        let now = Instant::now();
        let session = ActivitySession::for_phase("blocked-run", WorkflowPhase::Map);
        let outcome = ActivityRunOutcome::Terminal {
            status: "blocked".to_string(),
            findings: None,
            reason: Some("tool was refused before execution".to_string()),
        };

        let model = activity_heartbeat_model(&session, None, false, Some(&outcome), now);

        assert_eq!(model.tone, ActivityHeartbeatTone::Warning);
        assert!(model.text.contains("▣ BLOCKED"), "{}", model.text);
        assert!(!model.text.contains("✓ COMPLETE"), "{}", model.text);
        assert!(!model.text.contains("✗ FAILED"), "{}", model.text);
    }

    #[test]
    fn blocked_terminal_mapping_never_falls_through_to_complete() {
        let outcome = ActivityRunOutcome::Terminal {
            status: "blocked".to_string(),
            findings: None,
            reason: None,
        };

        let terminal = terminal_heartbeat(Some(&outcome));

        assert_eq!(terminal.label, "▣ BLOCKED");
        assert_eq!(terminal.tone, ActivityHeartbeatTone::Warning);
    }

    #[test]
    fn refused_terminal_activity_never_uses_a_success_heartbeat() {
        let now = Instant::now();
        let session = ActivitySession::for_phase("refused-run", WorkflowPhase::Scan);
        let outcome = ActivityRunOutcome::Terminal {
            status: "refused".to_string(),
            findings: None,
            reason: Some("policy refused the operation".to_string()),
        };

        let model = activity_heartbeat_model(&session, None, false, Some(&outcome), now);

        assert_eq!(model.tone, ActivityHeartbeatTone::Failed);
        assert!(model.text.contains("✗ FAILED"), "{}", model.text);
        assert!(!model.text.contains("✓ COMPLETE"), "{}", model.text);
    }

    #[test]
    fn operator_wait_never_uses_a_terminal_success_heartbeat() {
        let now = Instant::now();
        let session = ActivitySession::for_phase("waiting-run", WorkflowPhase::Scan);
        let outcome = ActivityRunOutcome::WaitingForOperator;

        let model = activity_heartbeat_model(&session, None, false, Some(&outcome), now);

        assert_eq!(model.tone, ActivityHeartbeatTone::Warning);
        assert!(model.text.contains("WAITING INPUT"), "{}", model.text);
        assert!(model.text.contains("run paused safely"), "{}", model.text);
        assert!(!model.text.contains("✓ COMPLETE"), "{}", model.text);
    }
}
