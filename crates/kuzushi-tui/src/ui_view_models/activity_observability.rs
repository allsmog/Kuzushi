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
    use kuzushi_core::WorkflowPhase;

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
        use kuzushi_core::run_lifecycle::{
            OperationFingerprint, RunCallId, RunId, RunItemEnvelopeV1, RunItemId, RunItemSource,
            RunItemV1, SafeText,
        };
        let start = RunItemEnvelopeV1::new(
            1,
            RunId::parse("model-run").unwrap(),
            RunItemId::new(),
            RunItemSource::Runtime,
            RunItemV1::ModelCallStarted {
                provider: SafeText::operator_visible("anthropic"),
                model: SafeText::operator_visible("claude"),
                operation_fingerprint: OperationFingerprint::from_bytes(b"threat-model synthesis"),
            },
            None,
        )
        .unwrap()
        .with_call(RunCallId::new())
        .unwrap();
        session.apply_run_item(start).unwrap();

        let stale_probe = Instant::now() + Duration::from_secs(45);
        let model = activity_heartbeat_model(
            &session,
            Some("threat-model:build"),
            true,
            None,
            stale_probe,
        );
        assert_eq!(model.tone, ActivityHeartbeatTone::Live, "{}", model.text);
        assert!(
            model.text.contains("◐ query in flight 45s"),
            "{}",
            model.text
        );
        assert!(!model.text.contains("NO PROGRESS SIGNAL"), "{}", model.text);

        let watchdog_probe = Instant::now() + Duration::from_secs(400);
        let escalated = activity_heartbeat_model(
            &session,
            Some("threat-model:build"),
            true,
            None,
            watchdog_probe,
        );
        assert_eq!(escalated.tone, ActivityHeartbeatTone::Stalled);
        assert!(
            escalated.text.contains("NO PROGRESS SIGNAL"),
            "{}",
            escalated.text
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
