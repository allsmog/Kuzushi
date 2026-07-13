use crate::{ActivitySession, DagTaskState};
use kuzushi_core::WorkflowPhase;
use std::time::{Duration, Instant};

pub(crate) const ACTIVITY_STALE_PROGRESS_AFTER: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityPhaseStripModel {
    pub(crate) phase: String,
    pub(crate) current: String,
    pub(crate) stage: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActivityHeartbeatTone {
    Live,
    Stalled,
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityHeartbeatModel {
    pub(crate) text: String,
    pub(crate) tone: ActivityHeartbeatTone,
}

pub(crate) fn activity_phase_strip_model(
    session: &ActivitySession,
    running_tool: Option<&str>,
) -> Option<ActivityPhaseStripModel> {
    let phase = session.origin_phase?;
    Some(ActivityPhaseStripModel {
        phase: phase_label(phase),
        current: current_subject(session, running_tool),
        stage: latest_progress_label(session),
    })
}

pub(crate) fn activity_heartbeat_model(
    session: &ActivitySession,
    running_tool: Option<&str>,
    live: bool,
    now: Instant,
) -> ActivityHeartbeatModel {
    let (age, source) = progress_signal(session, now);
    if !live {
        return ActivityHeartbeatModel {
            text: format!(
                " ✓ COMPLETE · last signal {} ago · {source}",
                age_label(age)
            ),
            tone: ActivityHeartbeatTone::Complete,
        };
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

fn phase_label(phase: WorkflowPhase) -> String {
    format!(
        "{} {} {}/{}",
        phase.kanji(),
        phase.word(),
        phase.position(),
        WorkflowPhase::ORDER.len()
    )
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

fn latest_progress_label(session: &ActivitySession) -> String {
    session
        .events
        .back()
        .map(|event| event.step.label.clone())
        .or_else(|| active_task(session).map(|task| task.last_label.clone()))
        .filter(|label| !label.trim().is_empty())
        .unwrap_or_else(|| "waiting for the first progress signal".to_string())
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
    use crate::{DagTaskRow, RecordedTraceEvent};
    use kuzushi_core::RunTraceStep;

    #[test]
    fn stale_live_activity_names_the_current_tool_and_last_real_signal() {
        let now = Instant::now();
        let mut session = ActivitySession::for_phase("context-run", WorkflowPhase::Map);
        session.events.push_back(RecordedTraceEvent {
            step: RunTraceStep::new(1, "tool-progress", "building repository inventory"),
            observed_at: now - Duration::from_secs(45),
        });

        let model = activity_heartbeat_model(&session, Some("context:build"), true, now);

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
    fn phase_strip_projects_current_context_stage_without_next_action_copy() {
        let mut session = ActivitySession::for_phase("context-run", WorkflowPhase::Map);
        let mut task = DagTaskRow::queued("context:build".into(), "context".into(), Vec::new());
        task.state = DagTaskState::Active;
        task.last_label = "mapping attack surface".to_string();
        session.tasks.insert(task.task_id.clone(), task);

        let model = activity_phase_strip_model(&session, Some("context:build")).unwrap();

        assert_eq!(model.phase, "組 map 1/4");
        assert_eq!(model.current, "context:build");
        assert_eq!(model.stage, "mapping attack surface");
    }
}
