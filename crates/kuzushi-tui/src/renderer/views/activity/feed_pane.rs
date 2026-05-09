use super::*;
use crate::app::is_hidden_module_id;
use crate::app::RecordedTraceEvent;
use std::time::{SystemTime, UNIX_EPOCH};

/// Build the right-pane feed line text for a recorded trace event. Returns an
/// empty string when the event should be hidden (subsystem event without
/// verbose toggle).
///
/// Format mirrors `design/mockups/_shared.jsx::logLine`: each line gets a
/// kind glyph (⏵ run, ✓ ok, ✗ err, ◆ agent, … flow, ▸ find, · log) so the
/// operator can scan the feed by event class without reading every label.
pub(crate) fn feed_event_text(
    event: &RecordedTraceEvent,
    verbose_subsystems: bool,
    width: usize,
) -> Option<String> {
    let module_id = event.step.module_id.as_deref().unwrap_or("");
    if !verbose_subsystems && !module_id.is_empty() && is_hidden_module_id(module_id) {
        return None;
    }

    let timestamp = event
        .step
        .started_at_ms
        .map(format_hh_mm_ss_from_ms)
        .unwrap_or_else(now_hh_mm_ss);
    let module_verb = match (
        event.step.module_id.as_deref(),
        event.step.verb.as_deref(),
    ) {
        (Some(module), Some(verb)) => format!("[{module}:{verb}]"),
        (Some(module), None) => format!("[{module}]"),
        _ => format!("[{}]", event.step.kind),
    };
    let indent = if event.step.parent_step.is_some() {
        "  ↳ "
    } else {
        " "
    };
    let glyph = feed_event_glyph(event);
    let body = format!(
        "{ts} {indent}{glyph} {tag} {label}",
        ts = timestamp,
        indent = indent,
        glyph = glyph,
        tag = module_verb,
        label = event.step.label
    );
    Some(fit(&body, width))
}

/// Glyph map matching `design/mockups/_shared.jsx::logLine` (lines 73-82):
///
/// | kind            | glyph | role         |
/// |-----------------|-------|--------------|
/// | tool / start    | ⏵     | run dispatch |
/// | done / complete | ✓     | ok           |
/// | refused / fail  | ✗     | err          |
/// | reasoning       | …     | flow         |
/// | tool-progress   | …     | flow         |
/// | tool-start      | ⏵     | run dispatch |
/// | tool-complete   | ✓     | ok           |
/// | finding         | ▸     | find         |
/// | (other)         | ·     | log          |
pub(crate) fn feed_event_glyph(event: &RecordedTraceEvent) -> &'static str {
    match event.step.severity.as_deref() {
        Some("danger") => "✗",
        _ => match event.step.kind.as_str() {
            "tool" | "tool-start" => "⏵",
            "done" | "tool-complete" => "✓",
            "refused" => "✗",
            "reasoning" | "tool-progress" => "…",
            "finding" | "find" => "▸",
            _ => "·",
        },
    }
}

pub(crate) fn feed_event_style(event: &RecordedTraceEvent) -> ratatui::style::Style {
    match event.step.severity.as_deref() {
        Some("danger") => theme::danger(),
        Some("warn") => theme::warn(),
        _ => match event.step.kind.as_str() {
            "tool" | "tool-start" => theme::primary(),
            "done" | "tool-complete" => theme::success(),
            "reasoning" | "tool-progress" => theme::muted(),
            "refused" => theme::danger(),
            "finding" | "find" => theme::warn(),
            _ => theme::subtle(),
        },
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
