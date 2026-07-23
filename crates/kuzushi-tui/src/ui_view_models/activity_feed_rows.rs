use super::activity_feed_pause::activity_feed_pause_model;
use super::activity_feed_placeholder::activity_feed_placeholder_model;
use crate::{ActivityRouteState, ActivitySession, DagTaskState, RecordedTraceEvent};
use std::collections::BTreeSet;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const STALLED_TRACE_AFTER_SECS: u64 = 30;
const LIVE_OUTPUT_EVENT_WINDOW: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActivityFeedRowTone {
    Primary,
    Success,
    Muted,
    Danger,
    Warn,
    Subtle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityFeedPaneRow {
    pub(crate) key: Option<kuzushi_core::run_lifecycle::RunCellKey>,
    pub(crate) disclosed_keys: BTreeSet<kuzushi_core::run_lifecycle::RunCellKey>,
    pub(crate) text: String,
    pub(crate) tone: ActivityFeedRowTone,
}

#[derive(Debug, Default)]
struct FeedOverflow {
    count: usize,
    disclosed_keys: BTreeSet<kuzushi_core::run_lifecycle::RunCellKey>,
}

pub(crate) fn activity_feed_pane_rows(
    session: &ActivitySession,
    route: &ActivityRouteState,
    width: usize,
    running_tool: Option<&str>,
    now: Instant,
) -> Vec<ActivityFeedPaneRow> {
    let typed = !session.run_projection.timeline.is_empty();
    let (mut rows, overflow) = visible_feed_rows(session, route, width, typed);
    prepend_feed_overflow_row(&mut rows, overflow, width, typed);
    append_feed_status_rows(&mut rows, session, route, running_tool, width, typed);
    if let Some(row) = stalled_trace_row(session, route, width, running_tool, now) {
        rows.push(row);
    }
    rows
}

pub(crate) fn activity_feed_viewport_rows(
    session: &ActivitySession,
    route: &ActivityRouteState,
    width: usize,
    height: usize,
    running_tool: Option<&str>,
    now: Instant,
) -> Vec<ActivityFeedPaneRow> {
    let rows = activity_feed_pane_rows(session, route, width, running_tool, now);
    bounded_feed_viewport(rows, route, width, height)
}

fn visible_feed_rows(
    session: &ActivitySession,
    route: &ActivityRouteState,
    width: usize,
    typed: bool,
) -> (Vec<ActivityFeedPaneRow>, FeedOverflow) {
    if typed {
        return visible_typed_rows(session, route, width);
    }
    let visible_count = visible_event_count(session.events.len(), route);
    let window_start = visible_count.saturating_sub(LIVE_OUTPUT_EVENT_WINDOW);
    let rows = session
        .events
        .iter()
        .take(visible_count)
        .skip(window_start)
        .flat_map(|event| feed_event_rows(event, route.verbose_subsystems, width))
        .collect();
    (
        rows,
        FeedOverflow {
            count: window_start,
            disclosed_keys: BTreeSet::new(),
        },
    )
}

fn visible_typed_rows(
    session: &ActivitySession,
    route: &ActivityRouteState,
    width: usize,
) -> (Vec<ActivityFeedPaneRow>, FeedOverflow) {
    typed_presentation_rows(session, route, width)
}

fn typed_presentation_rows(
    session: &ActivitySession,
    route: &ActivityRouteState,
    width: usize,
) -> (Vec<ActivityFeedPaneRow>, FeedOverflow) {
    let paused_projection = route.paused_event_count.map(|count| {
        kuzushi_core::run_lifecycle::reduce_run_items(
            session.run_projection.timeline.iter().take(count).cloned(),
        )
    });
    let projection = paused_projection
        .as_ref()
        .unwrap_or(&session.run_projection);
    let health = paused_projection.as_ref().map_or_else(
        || session.effective_run_lifecycle_health(),
        kuzushi_core::run_lifecycle::RunProjection::lifecycle_health,
    );
    let presentation = kuzushi_core::run_lifecycle::present_projection_with_hydration_and_health(
        projection,
        kuzushi_core::run_lifecycle::RunProjectionSource::TypedV1,
        &session.run_presentation_hydration,
        health,
    );
    let mut rows = Vec::new();
    append_typed_health_rows(&mut rows, &presentation, width);
    append_typed_summary_rows(&mut rows, &presentation, width);
    let overflow = append_typed_timeline_rows(&mut rows, &presentation, width);
    (rows, overflow)
}

fn append_typed_health_rows(
    rows: &mut Vec<ActivityFeedPaneRow>,
    presentation: &kuzushi_core::run_lifecycle::RunPresentationV1,
    width: usize,
) {
    rows.push(feed_section_row("HEALTH", width));
    let tone = lifecycle_health_tone(&presentation.health);
    rows.extend(
        presentation
            .overview_lines()
            .into_iter()
            .skip(1)
            .flat_map(|text| wrapped_feed_rows(None, BTreeSet::new(), &text, width, tone)),
    );
}

fn lifecycle_health_tone(
    health: &kuzushi_core::run_lifecycle::RunLifecycleHealth,
) -> ActivityFeedRowTone {
    use kuzushi_core::run_lifecycle::{
        ProjectionHealth, RunDeliveryHealth, RunDerivativeDeliveryHealth, RunDurabilityHealth,
    };
    if matches!(health.integrity, ProjectionHealth::Degraded { .. })
        || matches!(health.durability, RunDurabilityHealth::Failed { .. })
        || matches!(health.delivery, RunDeliveryHealth::Failed { .. })
    {
        return ActivityFeedRowTone::Danger;
    }
    if matches!(health.delivery, RunDeliveryHealth::CatchingUp { .. }) {
        return ActivityFeedRowTone::Warn;
    }
    if matches!(
        health.derivative_delivery,
        RunDerivativeDeliveryHealth::CatchingUp { .. } | RunDerivativeDeliveryHealth::Failed { .. }
    ) {
        return ActivityFeedRowTone::Warn;
    }
    ActivityFeedRowTone::Muted
}

fn append_typed_summary_rows(
    rows: &mut Vec<ActivityFeedPaneRow>,
    presentation: &kuzushi_core::run_lifecycle::RunPresentationV1,
    width: usize,
) {
    let mut active_section = None;
    for row in presentation.summary_text_rows() {
        if row.section != active_section {
            if let Some(section) = row.section.as_ref() {
                rows.push(feed_section_row(section.label(), width));
            }
            active_section = row.section.clone();
        }
        rows.extend(presentation_feed_rows(row, width));
    }
}

fn append_typed_timeline_rows(
    rows: &mut Vec<ActivityFeedPaneRow>,
    presentation: &kuzushi_core::run_lifecycle::RunPresentationV1,
    width: usize,
) -> FeedOverflow {
    let timeline = presentation.timeline_text_rows();
    if timeline.is_empty() {
        return FeedOverflow::default();
    }
    let omitted = timeline.len().saturating_sub(LIVE_OUTPUT_EVENT_WINDOW);
    let disclosed_keys = timeline
        .iter()
        .take(omitted)
        .map(|row| row.key.clone())
        .collect();
    rows.push(feed_section_row("TIMELINE", width));
    rows.extend(
        timeline
            .into_iter()
            .skip(omitted)
            .flat_map(|row| presentation_feed_rows(row, width)),
    );
    FeedOverflow {
        count: omitted,
        disclosed_keys,
    }
}

fn feed_section_row(label: &str, width: usize) -> ActivityFeedPaneRow {
    ActivityFeedPaneRow {
        key: None,
        disclosed_keys: BTreeSet::new(),
        text: fit(&format!(" ── {label}"), width),
        tone: ActivityFeedRowTone::Subtle,
    }
}

fn presentation_feed_rows(
    row: kuzushi_core::run_lifecycle::RunPresentationTextRowV1,
    width: usize,
) -> Vec<ActivityFeedPaneRow> {
    // The Run Focus header already owns the run's cost line; the typed
    // Terminal cell restating it here put cost on screen three times
    // (header + this row + the receipt notice). Header wins.
    if row.text.trim_start().starts_with("Cost · ") {
        return Vec::new();
    }
    let tone = presentation_row_tone(&row);
    wrapped_feed_rows(Some(row.key), BTreeSet::new(), &row.text, width, tone)
}

fn presentation_row_tone(
    row: &kuzushi_core::run_lifecycle::RunPresentationTextRowV1,
) -> ActivityFeedRowTone {
    if let Some(level) = row.diagnostic_level.as_ref() {
        return diagnostic_tone(level);
    }
    if let Some(status) = row.status {
        return presentation_status_tone(status);
    }
    match row.importance {
        kuzushi_core::run_lifecycle::RunCellImportanceV1::Essential => ActivityFeedRowTone::Primary,
        kuzushi_core::run_lifecycle::RunCellImportanceV1::Detail => ActivityFeedRowTone::Muted,
        kuzushi_core::run_lifecycle::RunCellImportanceV1::Diagnostic => ActivityFeedRowTone::Subtle,
    }
}

fn prepend_feed_overflow_row(
    rows: &mut Vec<ActivityFeedPaneRow>,
    overflow: FeedOverflow,
    width: usize,
    typed: bool,
) {
    if overflow.count > 0 {
        let detailed = if typed {
            let noun = pluralized(overflow.count, "timeline row", "timeline rows");
            format!(
                " {} {noun} omitted from Run Focus · inspect trace/replay",
                overflow.count,
            )
        } else {
            let noun = pluralized(overflow.count, "older event", "older events");
            format!(" {} {noun} retained in trace/replay", overflow.count,)
        };
        let compact = format!(" +{} timeline · replay", overflow.count);
        let text = disclosure_text(detailed, compact, width);
        rows.insert(
            0,
            ActivityFeedPaneRow {
                key: None,
                disclosed_keys: overflow.disclosed_keys,
                text,
                tone: ActivityFeedRowTone::Muted,
            },
        );
    }
}

fn pluralized(count: usize, singular: &'static str, plural: &'static str) -> &'static str {
    if count == 1 {
        singular
    } else {
        plural
    }
}

fn visible_event_count(available: usize, route: &ActivityRouteState) -> usize {
    route
        .paused_event_count
        .map(|count| count.min(available))
        .unwrap_or(available)
}

fn append_feed_status_rows(
    rows: &mut Vec<ActivityFeedPaneRow>,
    session: &ActivitySession,
    route: &ActivityRouteState,
    running_tool: Option<&str>,
    width: usize,
    typed: bool,
) {
    prepend_feed_pause_row(rows, route);
    append_feed_placeholder_row(rows, session, route, running_tool);
    append_legacy_terminal_rows(rows, session, width, typed);
    append_feed_acknowledgement(rows, session, width);
}

fn prepend_feed_pause_row(rows: &mut Vec<ActivityFeedPaneRow>, route: &ActivityRouteState) {
    if let Some(model) = activity_feed_pause_model(route) {
        rows.insert(
            0,
            ActivityFeedPaneRow {
                key: None,
                disclosed_keys: BTreeSet::new(),
                text: format!(" {}", model.text),
                tone: ActivityFeedRowTone::Warn,
            },
        );
    }
}

fn append_feed_placeholder_row(
    rows: &mut Vec<ActivityFeedPaneRow>,
    session: &ActivitySession,
    route: &ActivityRouteState,
    running_tool: Option<&str>,
) {
    if let (true, Some(model)) = (
        rows.is_empty(),
        activity_feed_placeholder_model(session, route, running_tool),
    ) {
        rows.push(ActivityFeedPaneRow {
            key: None,
            disclosed_keys: BTreeSet::new(),
            text: model.text,
            tone: ActivityFeedRowTone::Muted,
        });
    }
}

fn append_legacy_terminal_rows(
    rows: &mut Vec<ActivityFeedPaneRow>,
    session: &ActivitySession,
    width: usize,
    typed: bool,
) {
    if !typed {
        append_terminal_result_rows(rows, session, width);
    }
}

fn append_feed_acknowledgement(
    rows: &mut Vec<ActivityFeedPaneRow>,
    session: &ActivitySession,
    width: usize,
) {
    if let Some(acknowledgement) = session.operator_answer_acknowledgement.as_deref() {
        rows.push(ActivityFeedPaneRow {
            key: None,
            disclosed_keys: BTreeSet::new(),
            text: fit(&format!(" ✓ {acknowledgement}"), width),
            tone: ActivityFeedRowTone::Success,
        });
    }
}

fn append_terminal_result_rows(
    rows: &mut Vec<ActivityFeedPaneRow>,
    session: &ActivitySession,
    width: usize,
) {
    let Some(receipt) = session.run_focus_receipt.as_ref() else {
        return;
    };
    for result in &receipt.result_summaries {
        push_terminal_result(rows, result, width);
    }
}

fn push_terminal_result(
    rows: &mut Vec<ActivityFeedPaneRow>,
    result: &kuzushi_core::run_artifacts::RunResultSummary,
    width: usize,
) {
    rows.push(result_row(
        format!(
            " {} RESULT · {} · {}",
            result_glyph(&result.status),
            result.tool,
            result.status
        ),
        result_tone(&result.status),
        width,
    ));
    rows.push(result_row(
        format!("    {}", result.summary),
        ActivityFeedRowTone::Primary,
        width,
    ));
    let output_budget = if result.status == "completed" { 3 } else { 5 };
    for line in result.operator_output_preview(output_budget) {
        rows.push(result_row(
            format!("    │ {line}"),
            ActivityFeedRowTone::Muted,
            width,
        ));
    }
    push_result_messages(rows, result, width);
    push_result_artifacts(rows, result, width);
}

fn push_result_messages(
    rows: &mut Vec<ActivityFeedPaneRow>,
    result: &kuzushi_core::run_artifacts::RunResultSummary,
    width: usize,
) {
    for warning in result.warnings.iter().take(2) {
        rows.push(result_row(
            format!("    ⚠ {warning}"),
            ActivityFeedRowTone::Warn,
            width,
        ));
    }
    for error in result.errors.iter().take(2) {
        rows.push(result_row(
            format!("    ✗ {error}"),
            ActivityFeedRowTone::Danger,
            width,
        ));
    }
}

fn push_result_artifacts(
    rows: &mut Vec<ActivityFeedPaneRow>,
    result: &kuzushi_core::run_artifacts::RunResultSummary,
    width: usize,
) {
    if result.artifacts.is_empty() {
        return;
    }
    let labels = result
        .artifacts
        .iter()
        .take(3)
        .map(|artifact| artifact.label.as_str())
        .collect::<Vec<_>>()
        .join(" · ");
    let overflow = result.artifacts.len().saturating_sub(3);
    let suffix = (overflow > 0)
        .then(|| format!(" · +{overflow} more"))
        .unwrap_or_default();
    rows.push(result_row(
        format!("    ↳ artifacts: {labels}{suffix}"),
        ActivityFeedRowTone::Primary,
        width,
    ));
}

fn result_row(text: String, tone: ActivityFeedRowTone, width: usize) -> ActivityFeedPaneRow {
    ActivityFeedPaneRow {
        key: None,
        disclosed_keys: BTreeSet::new(),
        text: fit(&text, width),
        tone,
    }
}

fn result_tone(status: &str) -> ActivityFeedRowTone {
    match status {
        "completed" => ActivityFeedRowTone::Success,
        "failed" => ActivityFeedRowTone::Danger,
        "partial" => ActivityFeedRowTone::Warn,
        _ => ActivityFeedRowTone::Muted,
    }
}

fn result_glyph(status: &str) -> &'static str {
    match status {
        "completed" => "✓",
        "failed" => "✗",
        "partial" => "⚠",
        _ => "·",
    }
}

fn stalled_trace_row(
    session: &ActivitySession,
    route: &ActivityRouteState,
    width: usize,
    running_tool: Option<&str>,
    now: Instant,
) -> Option<ActivityFeedPaneRow> {
    if route.paused || !activity_is_live(session, running_tool) {
        return None;
    }
    let (elapsed, source) = trace_silence_elapsed(session, now)?;
    if elapsed.as_secs() < STALLED_TRACE_AFTER_SECS {
        return None;
    }
    // An open model call is quiet by nature — name it instead of implying
    // a stall, until it outlives the model-call watchdog.
    if let Some(query_age) = super::activity_observability::open_query_in_flight(session, now) {
        return Some(query_in_flight_row(query_age, width));
    }
    Some(ActivityFeedPaneRow {
        key: None,
        disclosed_keys: BTreeSet::new(),
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

fn query_in_flight_row(query_age: Duration, width: usize) -> ActivityFeedPaneRow {
    ActivityFeedPaneRow {
        key: None,
        disclosed_keys: BTreeSet::new(),
        text: fit(
            &format!(
                " ◐ query in flight {} · model call awaiting response",
                silence_duration_label(query_age)
            ),
            width,
        ),
        tone: ActivityFeedRowTone::Primary,
    }
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

fn presentation_status_tone(
    status: kuzushi_core::run_lifecycle::RunItemStatus,
) -> ActivityFeedRowTone {
    use kuzushi_core::run_lifecycle::RunItemStatus::*;
    match status {
        Completed => ActivityFeedRowTone::Success,
        Partial => ActivityFeedRowTone::Warn,
        Failed | Interrupted => ActivityFeedRowTone::Danger,
        Canceled | Skipped | Pending => ActivityFeedRowTone::Muted,
        Running => ActivityFeedRowTone::Primary,
    }
}

fn diagnostic_tone(level: &kuzushi_core::run_lifecycle::DiagnosticLevel) -> ActivityFeedRowTone {
    use kuzushi_core::run_lifecycle::DiagnosticLevel::*;
    match level {
        Info => ActivityFeedRowTone::Subtle,
        Warning => ActivityFeedRowTone::Warn,
        Error => ActivityFeedRowTone::Danger,
    }
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
            key: None,
            disclosed_keys: BTreeSet::new(),
            text: fit(&text, width),
            tone,
        }];
    }
    crate::renderer::shared::text::wrap_text(&text, width.max(16))
        .into_iter()
        .enumerate()
        .map(|(index, chunk)| ActivityFeedPaneRow {
            key: None,
            disclosed_keys: BTreeSet::new(),
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
    if feed_event_is_hidden(event, verbose_subsystems) {
        return None;
    }
    Some(format!(
        "{ts} {indent}{glyph} {tag} {label}",
        ts = feed_event_timestamp(event),
        indent = feed_event_indent(event),
        glyph = feed_event_glyph(event),
        tag = feed_event_tag(event),
        label = event.step.label
    ))
}

fn feed_event_is_hidden(event: &RecordedTraceEvent, verbose_subsystems: bool) -> bool {
    let module_id = event.step.module_id.as_deref().unwrap_or("");
    !verbose_subsystems && !module_id.is_empty() && crate::app::is_hidden_module_id(module_id)
}

fn feed_event_timestamp(event: &RecordedTraceEvent) -> String {
    event
        .step
        .started_at_ms
        .map(format_hh_mm_ss_from_ms)
        .unwrap_or_else(now_hh_mm_ss)
}

fn feed_event_tag(event: &RecordedTraceEvent) -> String {
    match (event.step.module_id.as_deref(), event.step.verb.as_deref()) {
        (Some(module), Some(verb)) => format!(
            "[{}]",
            crate::app::collapse_doubled_tail(&format!("{module}:{verb}"))
        ),
        (Some(module), None) => format!("[{module}]"),
        _ => format!("[{}]", event.step.kind),
    }
}

fn feed_event_indent(event: &RecordedTraceEvent) -> &'static str {
    if event.step.parent_step.is_some() {
        "  ↳ "
    } else {
        " "
    }
}

fn wrapped_feed_rows(
    key: Option<kuzushi_core::run_lifecycle::RunCellKey>,
    disclosed_keys: BTreeSet<kuzushi_core::run_lifecycle::RunCellKey>,
    text: &str,
    width: usize,
    tone: ActivityFeedRowTone,
) -> Vec<ActivityFeedPaneRow> {
    let body_width = width.saturating_sub(1).max(1);
    crate::renderer::shared::text::wrap_text(text, body_width)
        .into_iter()
        .map(|chunk| ActivityFeedPaneRow {
            key: key.clone(),
            disclosed_keys: disclosed_keys.clone(),
            text: format!(" {chunk}"),
            tone,
        })
        .collect()
}

fn bounded_feed_viewport(
    rows: Vec<ActivityFeedPaneRow>,
    route: &ActivityRouteState,
    width: usize,
    height: usize,
) -> Vec<ActivityFeedPaneRow> {
    if rows.len() <= height {
        return rows;
    }
    if height == 0 {
        return Vec::new();
    }
    if height == 1 {
        let keys = accounted_feed_keys(&rows);
        return vec![viewport_disclosure_row(rows.len(), "outside", keys, width)];
    }
    let requested = super::activity_scroll::activity_feed_scroll_offset(route, rows.len(), height);
    let anchor_tail = requested.saturating_add(height) >= rows.len();
    let (start, take) = viewport_bounds(rows.len(), height, requested, anchor_tail);
    assemble_feed_viewport(rows, start, take, width)
}

fn viewport_bounds(
    total: usize,
    height: usize,
    requested: usize,
    anchor_tail: bool,
) -> (usize, usize) {
    let mut take = height;
    let mut start = requested.min(total.saturating_sub(take));
    for _ in 0..2 {
        let disclosures = usize::from(start > 0) + usize::from(start + take < total);
        take = height.saturating_sub(disclosures);
        start = if anchor_tail {
            total.saturating_sub(take)
        } else {
            requested.min(total.saturating_sub(take))
        };
    }
    (start, take)
}

fn assemble_feed_viewport(
    rows: Vec<ActivityFeedPaneRow>,
    start: usize,
    take: usize,
    width: usize,
) -> Vec<ActivityFeedPaneRow> {
    let end = start.saturating_add(take).min(rows.len());
    let mut visible = Vec::new();
    append_top_viewport_disclosure(&mut visible, &rows, start, width);
    visible.extend(rows[start..end].iter().cloned());
    append_bottom_viewport_disclosure(&mut visible, &rows, end, width);
    visible
}

fn append_top_viewport_disclosure(
    visible: &mut Vec<ActivityFeedPaneRow>,
    rows: &[ActivityFeedPaneRow],
    start: usize,
    width: usize,
) {
    if start > 0 {
        visible.push(viewport_disclosure_row(
            start,
            "above",
            accounted_feed_keys(&rows[..start]),
            width,
        ));
    }
}

fn append_bottom_viewport_disclosure(
    visible: &mut Vec<ActivityFeedPaneRow>,
    rows: &[ActivityFeedPaneRow],
    end: usize,
    width: usize,
) {
    if end < rows.len() {
        visible.push(viewport_disclosure_row(
            rows.len() - end,
            "below",
            accounted_feed_keys(&rows[end..]),
            width,
        ));
    }
}

fn viewport_disclosure_row(
    count: usize,
    location: &str,
    disclosed_keys: BTreeSet<kuzushi_core::run_lifecycle::RunCellKey>,
    width: usize,
) -> ActivityFeedPaneRow {
    let detailed =
        format!(" {count} row(s) {location} Run Focus viewport · scroll or inspect/replay");
    let compact = format!(" +{count} {location} · replay");
    ActivityFeedPaneRow {
        key: None,
        disclosed_keys,
        text: disclosure_text(detailed, compact, width),
        tone: ActivityFeedRowTone::Muted,
    }
}

fn disclosure_text(detailed: String, compact: String, width: usize) -> String {
    if detailed.chars().count() <= width {
        return detailed;
    }
    if compact.chars().count() <= width {
        return compact;
    }
    let count = compact.split_whitespace().next().unwrap_or("+");
    format!(" {count} replay")
}

fn accounted_feed_keys(
    rows: &[ActivityFeedPaneRow],
) -> BTreeSet<kuzushi_core::run_lifecycle::RunCellKey> {
    rows.iter()
        .flat_map(|row| row.key.iter().chain(row.disclosed_keys.iter()))
        .cloned()
        .collect()
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
    fn typed_live_output_uses_canonical_keys_and_all_preview_lines() {
        use kuzushi_core::run_lifecycle::{present_projection, RunProjectionSource};
        let session = typed_live_session();
        let rows = activity_feed_pane_rows(
            &session,
            &ActivityRouteState::default(),
            180,
            None,
            Instant::now(),
        );
        let presentation =
            present_projection(&session.run_projection, RunProjectionSource::TypedV1);
        let rendered_keys = rows
            .iter()
            .filter_map(|row| row.key.clone())
            .collect::<std::collections::BTreeSet<_>>();

        assert_eq!(rendered_keys, presentation.semantic_keys());
        assert!(rows.iter().any(|row| row.text.contains("preview one")));
        assert!(rows.iter().any(|row| row.text.contains("preview two")));
        assert!(rows
            .iter()
            .any(|row| row.text.contains("warnings=1 errors=0")));
    }

    #[test]
    fn typed_live_output_uses_effective_delivery_health() {
        use kuzushi_core::run_lifecycle::CommittedRange;
        let mut session = typed_live_session();
        let applied = session.run_projection.last_committed_seq;
        session.observe_committed_range(CommittedRange {
            first_seq: applied + 1,
            through_seq: applied + 2,
        });

        let rows = typed_rows(&session);

        assert!(rows
            .iter()
            .any(|row| row.text.contains("Delivery: catching up")));
    }

    #[test]
    fn typed_live_output_quarantines_completion_after_durability_failure() {
        use kuzushi_core::run_lifecycle::{
            present_projection_with_hydration_and_health, PersistenceFailureStage, RunItemStatus,
            RunItemWriterFault, RunProjectionSource, SafeText,
        };
        let mut session = completed_live_session();
        session.record_run_item_writer_fault(RunItemWriterFault {
            stage: PersistenceFailureStage::Sync,
            last_durable_seq: session.run_projection.last_committed_seq,
            detail: SafeText::operator_visible("fixture sync failure"),
            execution_may_have_occurred: true,
        });

        let rows = typed_rows(&session);
        let presentation = present_projection_with_hydration_and_health(
            &session.run_projection,
            RunProjectionSource::TypedV1,
            &session.run_presentation_hydration,
            session.effective_run_lifecycle_health(),
        );

        assert_eq!(
            session.run_projection.terminal.as_ref().unwrap().status,
            RunItemStatus::Completed
        );
        assert_eq!(presentation.terminal_status, Some(RunItemStatus::Partial));
        assert_quarantined_completion_rows(&rows);
        assert_eq!(accounted_feed_keys(&rows), presentation.semantic_keys());
    }

    #[test]
    fn resolved_typed_question_is_non_actionable_without_losing_source_truth() {
        let (session, question_id) = resolved_question_session();
        let rows = typed_rows(&session);

        assert_resolved_question_rows(&rows);
        assert_resolved_question_source(&session, question_id, &rows);
    }

    fn resolved_question_session() -> (ActivitySession, kuzushi_core::run_lifecycle::RunQuestionId)
    {
        use kuzushi_core::run_lifecycle::{RunId, RunItemId, RunQuestionId};
        let run_id = RunId::parse("run-resolved-question").unwrap();
        let question_id = RunQuestionId::new();
        let item_id = RunItemId::new();
        let mut items = Vec::new();
        push_resolved_question_items(&mut items, &run_id, item_id, question_id);
        let mut session = ActivitySession::new(run_id.as_str());
        for item in items {
            session.apply_run_item(item).unwrap();
        }
        (session, question_id)
    }

    fn assert_resolved_question_rows(rows: &[ActivityFeedPaneRow]) {
        assert!(rows.iter().any(|row| row.text.contains("resolved")));
        assert!(!rows.iter().any(|row| {
            row.text.contains("Choose the scan scope.") || row.text.contains("Changed files")
        }));
    }

    fn assert_resolved_question_source(
        session: &ActivitySession,
        question_id: kuzushi_core::run_lifecycle::RunQuestionId,
        rows: &[ActivityFeedPaneRow],
    ) {
        use kuzushi_core::run_lifecycle::{present_projection, RunProjectionSource};
        let question = session.run_projection.questions.get(&question_id).unwrap();
        assert_eq!(question.prompt.as_str(), "Choose the scan scope.");
        assert!(question.decision.is_some());
        let expected = present_projection(&session.run_projection, RunProjectionSource::TypedV1)
            .semantic_keys();
        assert_eq!(accounted_feed_keys(rows), expected);
    }

    fn push_resolved_question_items(
        items: &mut Vec<kuzushi_core::run_lifecycle::RunItemEnvelopeV1>,
        run_id: &kuzushi_core::run_lifecycle::RunId,
        item_id: kuzushi_core::run_lifecycle::RunItemId,
        question_id: kuzushi_core::run_lifecycle::RunQuestionId,
    ) {
        push_item(items, run_id, item_id, question_item(question_id));
        push_item(items, run_id, item_id, decision_item(question_id));
    }

    fn question_item(
        question_id: kuzushi_core::run_lifecycle::RunQuestionId,
    ) -> kuzushi_core::run_lifecycle::RunItemV1 {
        use kuzushi_core::run_lifecycle::{OperatorChoice, RunItemV1, SafeText};
        RunItemV1::OperatorQuestion {
            question_id,
            prompt: SafeText::operator_visible("Choose the scan scope."),
            choices: vec![OperatorChoice {
                id: SafeText::operator_visible("choice-scope-0"),
                label: SafeText::operator_visible("Changed files"),
            }],
            authorization_scope: SafeText::operator_visible("scan scope"),
        }
    }

    fn decision_item(
        question_id: kuzushi_core::run_lifecycle::RunQuestionId,
    ) -> kuzushi_core::run_lifecycle::RunItemV1 {
        use kuzushi_core::run_lifecycle::{OperatorDecisionValue, RunItemV1, SafeText};
        RunItemV1::OperatorDecision {
            question_id,
            decision: OperatorDecisionValue::Selected {
                choice_id: SafeText::operator_visible("choice-scope-0"),
            },
            authorization_scope: SafeText::operator_visible("scan scope"),
        }
    }

    #[test]
    fn paused_typed_output_uses_the_same_health_prefix_as_replay() {
        use kuzushi_core::run_lifecycle::{PersistenceFailureStage, RunItemWriterFault, SafeText};
        let mut session = typed_live_session();
        session.record_run_item_writer_fault(RunItemWriterFault {
            stage: PersistenceFailureStage::Sync,
            last_durable_seq: session.run_projection.last_committed_seq,
            detail: SafeText::operator_visible("future sync failure"),
            execution_may_have_occurred: true,
        });
        let mut route = ActivityRouteState::default();
        route.paused = true;
        route.paused_event_count = Some(1);

        let rows = activity_feed_pane_rows(&session, &route, 180, None, Instant::now());

        assert!(rows
            .iter()
            .any(|row| row.text.contains("Durability: durable through seq 1")));
        assert!(rows
            .iter()
            .any(|row| row.text.contains("Delivery: current through seq 1")));
        assert!(!rows
            .iter()
            .any(|row| row.text.contains("future sync failure")));
    }

    #[test]
    fn typed_live_output_retains_summary_when_timeline_is_bounded() {
        use kuzushi_core::run_lifecycle::{present_projection, RunProjectionSource};
        let mut session = typed_live_session();
        append_timeline_notices(&mut session, LIVE_OUTPUT_EVENT_WINDOW + 4);

        let rows = typed_rows(&session);
        let expected = present_projection(&session.run_projection, RunProjectionSource::TypedV1)
            .semantic_keys();
        let rendered = rows
            .iter()
            .filter_map(|row| row.key.clone())
            .collect::<std::collections::BTreeSet<_>>();
        let omitted = expected.difference(&rendered).count();
        let disclosure = rows
            .iter()
            .find(|row| row.text.contains("timeline rows omitted from Run Focus"))
            .expect("bounded timeline disclosure");

        assert!(rows.iter().any(|row| row.text.contains("map target")));
        assert_eq!(omitted, 4);
        assert!(disclosure
            .text
            .contains(&format!("{omitted} timeline rows")));
        assert!(disclosure.text.contains("inspect trace/replay"));
        assert_eq!(accounted_feed_keys(&rows), expected);
    }

    #[test]
    fn narrow_typed_run_focus_wraps_without_losing_source_keys() {
        use kuzushi_core::run_lifecycle::{present_projection, RunProjectionSource};
        let session = typed_live_session();
        let rows = activity_feed_pane_rows(
            &session,
            &ActivityRouteState::default(),
            24,
            None,
            Instant::now(),
        );
        let expected = present_projection(&session.run_projection, RunProjectionSource::TypedV1)
            .semantic_keys();

        assert_eq!(accounted_feed_keys(&rows), expected);
        assert!(rows.iter().all(|row| row.text.chars().count() <= 24));
        assert!(!rows
            .iter()
            .filter(|row| row.key.is_some())
            .any(|row| row.text.ends_with('…')));
    }

    #[test]
    fn narrow_run_focus_height_discloses_offscreen_source_keys() {
        let mut session = typed_live_session();
        append_timeline_notices(&mut session, 20);
        let route = ActivityRouteState::default();
        let source_rows = activity_feed_pane_rows(&session, &route, 28, None, Instant::now());

        let viewport = activity_feed_viewport_rows(&session, &route, 28, 8, None, Instant::now());
        let disclosure = viewport
            .iter()
            .find(|row| row.text.contains("replay"))
            .expect("viewport omission disclosure");

        assert!(viewport.len() <= 8);
        assert_eq!(
            accounted_feed_keys(&viewport),
            accounted_feed_keys(&source_rows)
        );
        assert!(!disclosure.disclosed_keys.is_empty());
    }

    fn typed_rows(session: &ActivitySession) -> Vec<ActivityFeedPaneRow> {
        activity_feed_pane_rows(
            session,
            &ActivityRouteState::default(),
            180,
            None,
            Instant::now(),
        )
    }

    fn append_timeline_notices(session: &mut ActivitySession, count: usize) {
        use kuzushi_core::run_lifecycle::*;
        let run_id = RunId::parse("run-live-presentation").unwrap();
        for index in 0..count {
            let previous = session
                .run_projection
                .timeline
                .last()
                .map(|item| item.event_hash.clone());
            let notice = RunItemEnvelopeV1::new(
                session.run_projection.last_committed_seq + 1,
                run_id.clone(),
                RunItemId::new(),
                RunItemSource::Workflow,
                RunItemV1::DiagnosticNotice {
                    level: DiagnosticLevel::Info,
                    message: SafeText::operator_visible(format!("notice {index}")),
                },
                previous,
            )
            .unwrap();
            session.apply_run_item(notice).unwrap();
        }
    }

    fn typed_live_session() -> ActivitySession {
        use kuzushi_core::run_lifecycle::*;
        let run_id = RunId::parse("run-live-presentation").unwrap();
        let task_id = RunTaskId::new();
        let call_id = RunCallId::new();
        let call_item_id = RunItemId::new();
        let mut items = Vec::new();
        push_live_plan(&mut items, &run_id, task_id);
        push_live_task(&mut items, &run_id, task_id);
        push_live_call(&mut items, &run_id, task_id, call_id, call_item_id);
        let mut session = ActivitySession::new("run-live-presentation");
        for item in items {
            session.apply_run_item(item).unwrap();
        }
        session
    }

    fn completed_live_session() -> ActivitySession {
        use kuzushi_core::run_lifecycle::*;
        let run_id = RunId::parse("run-completed-presentation").unwrap();
        let mut items = Vec::new();
        push_item(
            &mut items,
            &run_id,
            RunItemId::new(),
            RunItemV1::PlanUpdated {
                revision: 1,
                title: SafeText::operator_visible("Map target"),
                status: RunItemStatus::Running,
                task_ids: Vec::new(),
            },
        );
        push_item(
            &mut items,
            &run_id,
            RunItemId::new(),
            RunItemV1::TerminalOutcome {
                status: RunItemStatus::Completed,
                summary: SafeText::operator_visible("recorded completion"),
                cost: kuzushi_core::runtime::RuntimeCostReport::INCOMPLETE_ZERO,
                continuation: WorkflowContinuation::OpenReport {
                    reason: SafeText::operator_visible("recorded completion"),
                },
            },
        );
        let mut session = ActivitySession::new(run_id.as_str());
        for item in items {
            session.apply_run_item(item).unwrap();
        }
        session
    }

    fn assert_quarantined_completion_rows(rows: &[ActivityFeedPaneRow]) {
        for forbidden in [
            "Plan r1 · completed",
            "Outcome · completed",
            "NEXT · open Report",
        ] {
            assert!(!rows.iter().any(|row| row.text.contains(forbidden)));
        }
        assert!(rows.iter().any(|row| row.text.contains("quarantined")));
        assert!(rows
            .iter()
            .any(|row| row.text.contains("Outcome · partial")));
        assert!(rows.iter().any(|row| row.text.contains("NEXT · inspect")));
        // C3: the Run Focus header owns the cost line — the typed Terminal
        // cell must not restate it in the feed.
        assert!(
            !rows.iter().any(|row| row.text.contains("Cost · ")),
            "typed Cost row leaked into the Run Focus feed"
        );
    }

    fn push_live_plan(
        items: &mut Vec<kuzushi_core::run_lifecycle::RunItemEnvelopeV1>,
        run_id: &kuzushi_core::run_lifecycle::RunId,
        task_id: kuzushi_core::run_lifecycle::RunTaskId,
    ) {
        use kuzushi_core::run_lifecycle::*;
        push_item(
            items,
            run_id,
            RunItemId::new(),
            RunItemV1::PlanUpdated {
                revision: 1,
                title: SafeText::operator_visible("map target"),
                status: RunItemStatus::Pending,
                task_ids: vec![task_id],
            },
        );
    }

    fn push_live_task(
        items: &mut Vec<kuzushi_core::run_lifecycle::RunItemEnvelopeV1>,
        run_id: &kuzushi_core::run_lifecycle::RunId,
        task_id: kuzushi_core::run_lifecycle::RunTaskId,
    ) {
        use kuzushi_core::run_lifecycle::*;
        push_task_item(
            items,
            run_id,
            RunItemId::new(),
            task_id,
            RunItemV1::TaskUpdated {
                title: SafeText::operator_visible("Build threat model"),
                status: RunItemStatus::Pending,
                detail: None,
            },
        );
    }

    fn push_live_call(
        items: &mut Vec<kuzushi_core::run_lifecycle::RunItemEnvelopeV1>,
        run_id: &kuzushi_core::run_lifecycle::RunId,
        task_id: kuzushi_core::run_lifecycle::RunTaskId,
        call_id: kuzushi_core::run_lifecycle::RunCallId,
        item_id: kuzushi_core::run_lifecycle::RunItemId,
    ) {
        push_live_call_request(items, run_id, task_id, call_id, item_id);
        push_live_call_start(items, run_id, task_id, call_id, item_id);
        push_live_call_finish(items, run_id, task_id, call_id, item_id);
    }

    fn push_live_call_request(
        items: &mut Vec<kuzushi_core::run_lifecycle::RunItemEnvelopeV1>,
        run_id: &kuzushi_core::run_lifecycle::RunId,
        task_id: kuzushi_core::run_lifecycle::RunTaskId,
        call_id: kuzushi_core::run_lifecycle::RunCallId,
        item_id: kuzushi_core::run_lifecycle::RunItemId,
    ) {
        use kuzushi_core::run_lifecycle::*;
        push_call_item(
            items,
            run_id,
            item_id,
            task_id,
            call_id,
            RunItemV1::ToolCallRequested {
                tool_name: SafeText::operator_visible("threat-model:build"),
                operation_fingerprint: OperationFingerprint::from_bytes(b"live-present"),
                safe_option_names: Vec::new(),
            },
        );
    }

    fn push_live_call_start(
        items: &mut Vec<kuzushi_core::run_lifecycle::RunItemEnvelopeV1>,
        run_id: &kuzushi_core::run_lifecycle::RunId,
        task_id: kuzushi_core::run_lifecycle::RunTaskId,
        call_id: kuzushi_core::run_lifecycle::RunCallId,
        item_id: kuzushi_core::run_lifecycle::RunItemId,
    ) {
        use kuzushi_core::run_lifecycle::*;
        push_call_item(
            items,
            run_id,
            item_id,
            task_id,
            call_id,
            RunItemV1::ToolCallStarted {
                tool_name: SafeText::operator_visible("threat-model:build"),
                runtime: Some(SafeText::operator_visible("agent")),
                model: Some(SafeText::operator_visible("model-x")),
            },
        );
    }

    fn push_live_call_finish(
        items: &mut Vec<kuzushi_core::run_lifecycle::RunItemEnvelopeV1>,
        run_id: &kuzushi_core::run_lifecycle::RunId,
        task_id: kuzushi_core::run_lifecycle::RunTaskId,
        call_id: kuzushi_core::run_lifecycle::RunCallId,
        item_id: kuzushi_core::run_lifecycle::RunItemId,
    ) {
        use kuzushi_core::run_lifecycle::*;
        push_call_item(
            items,
            run_id,
            item_id,
            task_id,
            call_id,
            RunItemV1::ToolCallFinished {
                status: RunItemStatus::Partial,
                cost: kuzushi_core::runtime::RuntimeCostReport::INCOMPLETE_ZERO,
                result_artifact: None,
                preview: vec![
                    SafeText::preview_line("preview one"),
                    SafeText::preview_line("preview two"),
                ],
                warning_count: 1,
                error_count: 0,
            },
        );
    }

    fn push_item(
        items: &mut Vec<kuzushi_core::run_lifecycle::RunItemEnvelopeV1>,
        run_id: &kuzushi_core::run_lifecycle::RunId,
        item_id: kuzushi_core::run_lifecycle::RunItemId,
        item: kuzushi_core::run_lifecycle::RunItemV1,
    ) {
        let previous = items.last().map(|item| item.event_hash.clone());
        items.push(
            kuzushi_core::run_lifecycle::RunItemEnvelopeV1::new(
                items.len() as u64 + 1,
                run_id.clone(),
                item_id,
                kuzushi_core::run_lifecycle::RunItemSource::Workflow,
                item,
                previous,
            )
            .unwrap(),
        );
    }

    fn push_task_item(
        items: &mut Vec<kuzushi_core::run_lifecycle::RunItemEnvelopeV1>,
        run_id: &kuzushi_core::run_lifecycle::RunId,
        item_id: kuzushi_core::run_lifecycle::RunItemId,
        task_id: kuzushi_core::run_lifecycle::RunTaskId,
        item: kuzushi_core::run_lifecycle::RunItemV1,
    ) {
        push_item(items, run_id, item_id, item);
        let envelope = items.pop().unwrap().with_task(task_id).unwrap();
        items.push(envelope);
    }

    fn push_call_item(
        items: &mut Vec<kuzushi_core::run_lifecycle::RunItemEnvelopeV1>,
        run_id: &kuzushi_core::run_lifecycle::RunId,
        item_id: kuzushi_core::run_lifecycle::RunItemId,
        task_id: kuzushi_core::run_lifecycle::RunTaskId,
        call_id: kuzushi_core::run_lifecycle::RunCallId,
        item: kuzushi_core::run_lifecycle::RunItemV1,
    ) {
        push_item(items, run_id, item_id, item);
        let envelope = items
            .pop()
            .unwrap()
            .with_task(task_id)
            .unwrap()
            .with_call(call_id)
            .unwrap();
        items.push(envelope);
    }

    #[test]
    fn activity_feed_pane_rows_filters_hidden_events_until_verbose() {
        let mut session = ActivitySession::new("r-1");
        let mut route = ActivityRouteState::default();
        session.apply_step(
            RunTraceStep::new(1, "reasoning", "index")
                .with_module_id("pipeline")
                .with_started_at_ms(3_661_000),
        );

        let rows = activity_feed_pane_rows(&session, &route, 80, None, Instant::now());
        assert_eq!(rows.len(), 1);
        assert!(rows[0].text.contains("hidden subsystem event"));
        assert_eq!(rows[0].tone, ActivityFeedRowTone::Muted);

        route.verbose_subsystems = true;
        let rows = activity_feed_pane_rows(&session, &route, 80, None, Instant::now());
        assert_eq!(rows.len(), 1);
        assert!(rows[0].text.contains("[pipeline]"));
        assert_eq!(rows[0].tone, ActivityFeedRowTone::Muted);
    }

    #[test]
    fn activity_feed_pane_rows_adds_pause_before_events() {
        let mut session = ActivitySession::new("r-1");
        let mut route = ActivityRouteState::default();
        route.paused = true;
        session.apply_step(
            RunTraceStep::new(1, "done", "complete")
                .with_module_id("semgrep")
                .with_verb("scan")
                .with_started_at_ms(42_000),
        );

        let rows = activity_feed_pane_rows(&session, &route, 80, None, Instant::now());

        assert_eq!(rows[0].tone, ActivityFeedRowTone::Warn);
        assert!(rows[0].text.contains("paused"));
        assert_eq!(rows[1].tone, ActivityFeedRowTone::Success);
        assert!(rows[1].text.contains("[semgrep:scan]"));
    }

    #[test]
    fn activity_feed_retains_operator_answer_acknowledgement_after_completion() {
        let mut session = ActivitySession::new("r-1");
        session.operator_answer_acknowledgement =
            Some("accepted Repository · run resumed".to_string());
        let route = ActivityRouteState::default();

        let rows = activity_feed_pane_rows(&session, &route, 80, None, Instant::now());

        let acknowledgement = rows.last().expect("answer acknowledgement");
        assert_eq!(acknowledgement.tone, ActivityFeedRowTone::Success);
        assert!(acknowledgement.text.contains("accepted Repository"));
    }

    #[test]
    fn terminal_result_rows_preserve_output_warning_and_artifact_semantics() {
        let mut session = ActivitySession::new("r-result");
        session.mark_run_focus_terminal_pending("partial");
        session
            .run_focus_receipt
            .as_mut()
            .expect("terminal receipt")
            .result_summaries
            .push(partial_result_summary_fixture());

        let rows = activity_feed_pane_rows(
            &session,
            &ActivityRouteState::default(),
            120,
            None,
            Instant::now(),
        );

        assert!(rows
            .iter()
            .any(|row| row.text.contains("RESULT · threat-model:build · partial")));
        assert!(rows.iter().any(|row| row.text.contains("Threats: 0")));
        assert!(rows
            .iter()
            .any(|row| row.text.contains("Cost: >=$0.0000 (incomplete)")));
        assert!(rows
            .iter()
            .any(|row| row.text.contains("select another target")));
        assert!(rows
            .iter()
            .any(|row| row.text.contains("normalized threat model")));
    }

    fn partial_result_summary_fixture() -> kuzushi_core::run_artifacts::RunResultSummary {
        kuzushi_core::run_artifacts::RunResultSummary {
            run_id: "r-result".to_string(),
            tool: "threat-model:build".to_string(),
            status: "partial".to_string(),
            summary: "no concrete threat-model evidence".to_string(),
            output_lines: [
                "Method: STRIDE",
                "Saved: previous model preserved",
                "Threats: 0",
                "DFD: 1 node",
                "Findings: 0",
                "Cost: >=$0.0000 (incomplete)",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            output_line_count: 6,
            warnings: vec!["select another target".to_string()],
            warning_count: 1,
            errors: Vec::new(),
            error_count: 0,
            artifacts: vec![kuzushi_core::RunArtifact {
                label: "normalized threat model".to_string(),
                path: "threat-model.json".to_string(),
                kind: "json".to_string(),
            }],
            artifact_count: 1,
        }
    }

    #[test]
    fn activity_feed_pane_rows_warns_when_live_trace_output_stalls() {
        let now = Instant::now();
        let mut session = ActivitySession::new("r-1");
        let route = ActivityRouteState::default();
        session.started_at = now - Duration::from_secs(60);
        session.events.push_back(RecordedTraceEvent {
            step: RunTraceStep::new(1, "reasoning", "started").with_module_id("triage"),
            observed_at: now - Duration::from_secs(45),
        });

        let rows = activity_feed_pane_rows(&session, &route, 80, Some("triage:run"), now);

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
        let route = ActivityRouteState::default();
        session.started_at = now - Duration::from_secs(31);

        let rows = activity_feed_pane_rows(&session, &route, 80, Some("threat-model:build"), now);

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
        let mut route = ActivityRouteState::default();
        session.started_at = now - Duration::from_secs(90);

        let idle_rows = activity_feed_pane_rows(&session, &route, 80, None, now);
        assert!(!idle_rows
            .iter()
            .any(|row| row.text.contains("no trace output")));

        route.paused = true;
        let paused_rows = activity_feed_pane_rows(&session, &route, 80, Some("sast:scan"), now);
        assert!(!paused_rows
            .iter()
            .any(|row| row.text.contains("no trace output")));
    }

    #[test]
    fn live_output_windows_events_before_formatting() {
        let mut session = ActivitySession::new("r-window");
        for index in 0..600 {
            session.apply_step(
                RunTraceStep::new(index, "reasoning", format!("event-{index:03}"))
                    .with_module_id("semgrep")
                    .with_verb("run"),
            );
        }

        let rows = activity_feed_pane_rows(
            &session,
            &ActivityRouteState::default(),
            120,
            None,
            Instant::now(),
        );

        assert!(rows[0].text.contains("88 older events retained"));
        assert!(!rows.iter().any(|row| row.text.contains("event-087")));
        assert!(rows.iter().any(|row| row.text.contains("event-599")));
    }
}
