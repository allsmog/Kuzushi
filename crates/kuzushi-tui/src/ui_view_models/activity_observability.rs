use super::activity_header::ActivityRunOutcome;
use crate::{ActivitySession, DagTaskState};
use std::time::{Duration, Instant};

pub(crate) const ACTIVITY_STALE_PROGRESS_AFTER: Duration = Duration::from_secs(30);

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
        return ActivityHeartbeatModel {
            text: format!(
                " ⚠ NO PROGRESS SIGNAL for {} · current {} · last {source} · Ctrl+C cancels",
                age_label(age),
                current_subject(session, running_tool),
            ),
            tone: ActivityHeartbeatTone::Stalled,
        };
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
        .or_else(|| active_task(session).map(|task| task.task_id.clone()))
        .unwrap_or_else(|| "run finalization".to_string())
}

fn active_task(session: &ActivitySession) -> Option<&crate::DagTaskRow> {
    session
        .tasks
        .values()
        .find(|task| matches!(task.state, DagTaskState::Active | DagTaskState::Canceling))
}

fn progress_signal(session: &ActivitySession, now: Instant) -> (Duration, String) {
    let (observed_at, label) = session
        .events
        .back()
        .map(|event| (event.observed_at, event.step.label.clone()))
        .unwrap_or((session.started_at, "run started".to_string()));
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
    use crate::RecordedTraceEvent;
    use kuzushi_core::{RunTraceStep, WorkflowPhase};

    #[test]
    fn stale_live_activity_names_the_current_tool_and_last_real_signal() {
        let now = Instant::now();
        let mut session = ActivitySession::for_phase("context-run", WorkflowPhase::Map);
        session.events.push_back(RecordedTraceEvent {
            step: RunTraceStep::new(1, "tool-progress", "building repository inventory"),
            observed_at: now - Duration::from_secs(45),
        });

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
            model.text.contains("building repository inventory"),
            "{}",
            model.text
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
