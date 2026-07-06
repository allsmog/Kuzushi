use super::activity_feed_pause::activity_feed_pause_model;
use super::activity_feed_placeholder::activity_feed_placeholder_model;
use crate::{ActivitySession, DagTaskState, RecordedTraceEvent};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const STALLED_TRACE_AFTER_SECS: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActivityFeedRowTone {
    Primary,
    Label,
    Success,
    Muted,
    Danger,
    Warn,
    Subtle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityFeedPaneRow {
    pub(crate) text: String,
    pub(crate) tone: ActivityFeedRowTone,
}

pub(crate) fn activity_feed_pane_rows(
    session: &ActivitySession,
    width: usize,
    running_tool: Option<&str>,
    now: Instant,
) -> Vec<ActivityFeedPaneRow> {
    let visible_events = session
        .paused_event_count
        .map(|count| count.min(session.events.len()))
        .unwrap_or(session.events.len());
    let mut rows = session
        .events
        .iter()
        .take(visible_events)
        .flat_map(|event| feed_event_rows(event, session.verbose_subsystems, width))
        .collect::<Vec<_>>();
    if let Some(model) = activity_feed_pause_model(session) {
        rows.insert(
            0,
            ActivityFeedPaneRow {
                text: format!(" {}", model.text),
                tone: ActivityFeedRowTone::Warn,
            },
        );
    }
    if let (true, Some(model)) = (
        rows.is_empty(),
        activity_feed_placeholder_model(session, running_tool),
    ) {
        rows.push(ActivityFeedPaneRow {
            text: model.text,
            tone: ActivityFeedRowTone::Muted,
        });
    }
    if let Some(row) = stalled_trace_row(session, width, running_tool, now) {
        rows.push(row);
    }
    rows
}

fn stalled_trace_row(
    session: &ActivitySession,
    width: usize,
    running_tool: Option<&str>,
    now: Instant,
) -> Option<ActivityFeedPaneRow> {
    if session.paused || !activity_is_live(session, running_tool) {
        return None;
    }
    let (elapsed, source) = trace_silence_elapsed(session, now)?;
    (elapsed.as_secs() >= STALLED_TRACE_AFTER_SECS).then(|| ActivityFeedPaneRow {
        text: fit(
            &format!(
                " ⚠ no trace output for {} since {source}",
                silence_duration_label(elapsed)
            ),
            width,
        ),
        tone: ActivityFeedRowTone::Warn,
    })
}

fn activity_is_live(session: &ActivitySession, running_tool: Option<&str>) -> bool {
    running_tool.is_some()
        || session
            .tasks
            .values()
            .any(|row| row.state == DagTaskState::Active)
}

fn trace_silence_elapsed(
    session: &ActivitySession,
    now: Instant,
) -> Option<(Duration, &'static str)> {
    if let Some(event) = session.events.back() {
        return now
            .checked_duration_since(event.observed_at)
            .map(|elapsed| (elapsed, "last trace event"));
    }
    now.checked_duration_since(session.started_at)
        .map(|elapsed| (elapsed, "run start"))
}

fn silence_duration_label(elapsed: Duration) -> String {
    let seconds = elapsed.as_secs();
    if seconds < 60 {
        return format!("{seconds}s");
    }
    format!("{}m{:02}s", seconds / 60, seconds % 60)
}

/// One event, one or more pane rows. Error rows (danger severity, refusals)
/// carry the remedy the operator must read, so they wrap onto indented
/// continuation rows; routine progress events stay single-line. The scroll
/// model counts produced rows, so multi-row events tail and clamp correctly.
fn feed_event_rows(
    event: &RecordedTraceEvent,
    verbose_subsystems: bool,
    width: usize,
) -> Vec<ActivityFeedPaneRow> {
    let Some(text) = feed_event_text(event, verbose_subsystems) else {
        return Vec::new();
    };
    let tone = feed_event_tone(event);
    if !matches!(
        tone,
        ActivityFeedRowTone::Danger | ActivityFeedRowTone::Warn
    ) {
        return vec![ActivityFeedPaneRow {
            text: fit(&text, width),
            tone,
        }];
    }
    crate::renderer::shared::text::wrap_text(&text, width.max(16))
        .into_iter()
        .enumerate()
        .map(|(index, chunk)| ActivityFeedPaneRow {
            text: if index == 0 {
                chunk
            } else {
                format!("    {chunk}")
            },
            tone,
        })
        .collect()
}

fn feed_event_text(event: &RecordedTraceEvent, verbose_subsystems: bool) -> Option<String> {
    let module_id = event.step.module_id.as_deref().unwrap_or("");
    if !verbose_subsystems && !module_id.is_empty() && crate::app::is_hidden_module_id(module_id) {
        return None;
    }

    let timestamp = event
        .step
        .started_at_ms
        .map(format_hh_mm_ss_from_ms)
        .unwrap_or_else(now_hh_mm_ss);
    let module_verb = match (event.step.module_id.as_deref(), event.step.verb.as_deref()) {
        (Some(module), Some(verb)) => {
            format!(
                "[{}]",
                crate::app::collapse_doubled_tail(&format!("{module}:{verb}"))
            )
        }
        (Some(module), None) => format!("[{module}]"),
        _ => format!("[{}]", event.step.kind),
    };
    let indent = if event.step.parent_step.is_some() {
        "  ↳ "
    } else {
        " "
    };
    Some(format!(
        "{ts} {indent}{glyph} {tag} {label}",
        ts = timestamp,
        indent = indent,
        glyph = feed_event_glyph(event),
        tag = module_verb,
        label = event.step.label
    ))
}

fn feed_event_glyph(event: &RecordedTraceEvent) -> &'static str {
    match event.step.severity.as_deref() {
        Some("danger") => "✗",
        _ => match event.step.kind.as_str() {
            "tool" | "tool-start" => "⏵",
            "done" | "tool-complete" => "✓",
            "refused" => "✗",
            "reasoning" | "tool-progress" => "…",
            "finding" | "find" => "◇",
            _ => "·",
        },
    }
}

fn feed_event_tone(event: &RecordedTraceEvent) -> ActivityFeedRowTone {
    severity_event_tone(event).unwrap_or_else(|| kind_event_tone(event.step.kind.as_str()))
}

fn severity_event_tone(event: &RecordedTraceEvent) -> Option<ActivityFeedRowTone> {
    match event.step.severity.as_deref()? {
        "danger" => Some(ActivityFeedRowTone::Danger),
        "warn" => Some(ActivityFeedRowTone::Warn),
        _ => None,
    }
}

fn kind_event_tone(kind: &str) -> ActivityFeedRowTone {
    match kind {
        "tool" | "tool-start" => ActivityFeedRowTone::Primary,
        "done" | "tool-complete" => ActivityFeedRowTone::Success,
        "reasoning" | "tool-progress" => ActivityFeedRowTone::Muted,
        "refused" => ActivityFeedRowTone::Danger,
        "finding" | "find" => ActivityFeedRowTone::Warn,
        _ => ActivityFeedRowTone::Subtle,
    }
}

fn format_hh_mm_ss_from_ms(ms: u64) -> String {
    let secs_in_day = 86_400u64;
    let secs = (ms / 1000) % secs_in_day;
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

fn now_hh_mm_ss() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_hh_mm_ss_from_ms(secs * 1000)
}

fn fit(value: &str, width: usize) -> String {
    let len = value.chars().count();
    if len <= width {
        return value.to_string();
    }
    if width <= 1 {
        return value.chars().take(width).collect();
    }
    format!("{}…", value.chars().take(width - 1).collect::<String>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::RunTraceStep;

    #[test]
    fn activity_feed_pane_rows_filters_hidden_events_until_verbose() {
        let mut session = ActivitySession::new("r-1");
        session.apply_step(
            RunTraceStep::new(1, "reasoning", "index")
                .with_module_id("pipeline")
                .with_started_at_ms(3_661_000),
        );

        let rows = activity_feed_pane_rows(&session, 80, None, Instant::now());
        assert_eq!(rows.len(), 1);
        assert!(rows[0].text.contains("hidden subsystem event"));
        assert_eq!(rows[0].tone, ActivityFeedRowTone::Muted);

        session.verbose_subsystems = true;
        let rows = activity_feed_pane_rows(&session, 80, None, Instant::now());
        assert_eq!(rows.len(), 1);
        assert!(rows[0].text.contains("[pipeline]"));
        assert_eq!(rows[0].tone, ActivityFeedRowTone::Muted);
    }

    #[test]
    fn activity_feed_pane_rows_adds_pause_before_events() {
        let mut session = ActivitySession::new("r-1");
        session.paused = true;
        session.apply_step(
            RunTraceStep::new(1, "done", "complete")
                .with_module_id("semgrep")
                .with_verb("scan")
                .with_started_at_ms(42_000),
        );

        let rows = activity_feed_pane_rows(&session, 80, None, Instant::now());

        assert_eq!(rows[0].tone, ActivityFeedRowTone::Warn);
        assert!(rows[0].text.contains("paused"));
        assert_eq!(rows[1].tone, ActivityFeedRowTone::Success);
        assert!(rows[1].text.contains("[semgrep:scan]"));
    }

    #[test]
    fn activity_feed_pane_rows_warns_when_live_trace_output_stalls() {
        let now = Instant::now();
        let mut session = ActivitySession::new("r-1");
        session.started_at = now - Duration::from_secs(60);
        session.events.push_back(RecordedTraceEvent {
            step: RunTraceStep::new(1, "reasoning", "started").with_module_id("triage"),
            observed_at: now - Duration::from_secs(45),
        });

        let rows = activity_feed_pane_rows(&session, 80, Some("triage:run"), now);

        let stalled = rows
            .iter()
            .find(|row| row.text.contains("no trace output"))
            .expect("stalled trace row");
        assert_eq!(stalled.tone, ActivityFeedRowTone::Warn);
        assert!(stalled.text.contains("45s since last trace event"));
    }

    #[test]
    fn activity_feed_pane_rows_warns_when_live_run_never_emits_trace() {
        let now = Instant::now();
        let mut session = ActivitySession::new("r-1");
        session.started_at = now - Duration::from_secs(31);

        let rows = activity_feed_pane_rows(&session, 80, Some("threat-model:build"), now);

        assert!(rows
            .iter()
            .any(|row| row.text.contains("waiting for its first trace event")));
        assert!(rows
            .iter()
            .any(|row| row.text.contains("31s since run start")));
    }

    #[test]
    fn activity_feed_pane_rows_does_not_warn_for_idle_or_paused_sessions() {
        let now = Instant::now();
        let mut session = ActivitySession::new("r-1");
        session.started_at = now - Duration::from_secs(90);

        let idle_rows = activity_feed_pane_rows(&session, 80, None, now);
        assert!(!idle_rows
            .iter()
            .any(|row| row.text.contains("no trace output")));

        session.paused = true;
        let paused_rows = activity_feed_pane_rows(&session, 80, Some("sast:scan"), now);
        assert!(!paused_rows
            .iter()
            .any(|row| row.text.contains("no trace output")));
    }
}
