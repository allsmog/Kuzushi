use super::activity_feed_pause::activity_feed_pause_model;
use super::activity_feed_placeholder::activity_feed_placeholder_model;
use crate::renderer::shared::text::{display_width, fit};
use crate::{ActivityRouteState, ActivitySession, DagTaskState};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

const STALLED_PROGRESS_AFTER_SECS: u64 = 30;
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
    let (mut rows, overflow) = visible_feed_rows(session, route, width);
    prepend_feed_overflow_row(&mut rows, overflow, width);
    append_feed_status_rows(&mut rows, session, route, running_tool, width);
    if let Some(row) = stalled_progress_row(session, route, width, running_tool, now) {
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
    if route.paused || route.verbose_subsystems || !lifecycle_health_is_normal(&presentation.health)
    {
        append_typed_health_rows(&mut rows, &presentation, width);
    }
    if route.verbose_subsystems {
        append_typed_summary_rows(&mut rows, &presentation, width);
    } else {
        append_typed_summary_disclosure(&mut rows, &presentation, width);
    }
    let overflow =
        append_typed_timeline_rows(&mut rows, &presentation, width, route.verbose_subsystems);
    (rows, overflow)
}

fn append_typed_summary_disclosure(
    rows: &mut Vec<ActivityFeedPaneRow>,
    presentation: &kuzushi_core::run_lifecycle::RunPresentationV1,
    width: usize,
) {
    let keys = presentation
        .summary
        .iter()
        .flat_map(|section| section.cells.iter().map(|cell| cell.key.clone()))
        .collect::<BTreeSet<_>>();
    if keys.is_empty() {
        return;
    }
    rows.push(ActivityFeedPaneRow {
        key: None,
        disclosed_keys: keys,
        text: fit(" + run details available · V expands", width),
        tone: ActivityFeedRowTone::Subtle,
    });
}

fn lifecycle_health_is_normal(health: &kuzushi_core::run_lifecycle::RunLifecycleHealth) -> bool {
    use kuzushi_core::run_lifecycle::{
        ProjectionHealth, RunDeliveryHealth, RunDerivativeDeliveryHealth, RunDurabilityHealth,
        RunProgressFidelity,
    };
    matches!(health.integrity, ProjectionHealth::Healthy)
        && matches!(health.durability, RunDurabilityHealth::Durable { .. })
        && matches!(health.progress, RunProgressFidelity::Complete)
        && matches!(health.delivery, RunDeliveryHealth::Current { .. })
        && matches!(
            health.derivative_delivery,
            RunDerivativeDeliveryHealth::NotObserved | RunDerivativeDeliveryHealth::Current { .. }
        )
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
    let header_owned_cost_rows = run_focus_header_owned_cost_rows(presentation);
    let visible_rows = presentation
        .summary_text_rows()
        .into_iter()
        .filter(|row| !header_owned_cost_rows.contains(&(row.key.clone(), row.text.clone())));
    for row in visible_rows {
        if row.section != active_section {
            if let Some(section) = row.section.as_ref() {
                rows.push(feed_section_row(section.label(), width));
            }
            active_section = row.section.clone();
        }
        rows.extend(presentation_feed_rows(row, width));
    }
}

fn run_focus_header_owned_cost_rows(
    presentation: &kuzushi_core::run_lifecycle::RunPresentationV1,
) -> BTreeSet<(kuzushi_core::run_lifecycle::RunCellKey, String)> {
    presentation
        .summary
        .iter()
        .flat_map(|section| section.cells.iter())
        .filter_map(|cell| {
            let kuzushi_core::run_lifecycle::RunPresentationPayloadV1::Terminal(terminal) =
                &cell.payload
            else {
                return None;
            };
            Some((
                cell.key.clone(),
                format!(
                    "Cost · {}",
                    kuzushi_core::run_lifecycle::cost_label(terminal.cost)
                ),
            ))
        })
        .collect()
}

fn append_typed_timeline_rows(
    rows: &mut Vec<ActivityFeedPaneRow>,
    presentation: &kuzushi_core::run_lifecycle::RunPresentationV1,
    width: usize,
    verbose: bool,
) -> FeedOverflow {
    let timeline = presentation.timeline_text_rows();
    if timeline.is_empty() {
        return FeedOverflow::default();
    }
    let (visible, hidden) = typed_timeline_visibility(&timeline, verbose);
    let omitted = visible.len().saturating_sub(LIVE_OUTPUT_EVENT_WINDOW);
    let disclosed_keys = visible
        .iter()
        .take(omitted)
        .map(|row| row.key.clone())
        .collect();
    rows.push(feed_section_row("ACTIVITY", width));
    append_hidden_detail_row(rows, &hidden, width);
    rows.extend(
        visible
            .into_iter()
            .skip(omitted)
            .flat_map(|row| presentation_feed_rows(row.clone(), width)),
    );
    FeedOverflow {
        count: omitted,
        disclosed_keys,
    }
}

fn typed_timeline_visibility<'a>(
    timeline: &'a [kuzushi_core::run_lifecycle::RunPresentationTextRowV1],
    verbose: bool,
) -> (
    Vec<&'a kuzushi_core::run_lifecycle::RunPresentationTextRowV1>,
    Vec<&'a kuzushi_core::run_lifecycle::RunPresentationTextRowV1>,
) {
    let is_visible = |row: &&kuzushi_core::run_lifecycle::RunPresentationTextRowV1| {
        verbose || row.importance != kuzushi_core::run_lifecycle::RunCellImportanceV1::Detail
    };
    let visible = timeline.iter().filter(is_visible).collect();
    let hidden = timeline.iter().filter(|row| !is_visible(row)).collect();
    (visible, hidden)
}

fn append_hidden_detail_row(
    rows: &mut Vec<ActivityFeedPaneRow>,
    hidden: &[&kuzushi_core::run_lifecycle::RunPresentationTextRowV1],
    width: usize,
) {
    if hidden.is_empty() {
        return;
    }
    rows.push(ActivityFeedPaneRow {
        key: None,
        disclosed_keys: hidden.iter().map(|row| row.key.clone()).collect(),
        text: fit(
            &format!("    +{} low-level event(s) · V shows details", hidden.len()),
            width,
        ),
        tone: ActivityFeedRowTone::Subtle,
    });
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
) {
    if overflow.count > 0 {
        let noun = pluralized(overflow.count, "timeline row", "timeline rows");
        let detailed = format!(
            " {} {noun} omitted from Run Focus · inspect trace/replay",
            overflow.count,
        );
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

fn append_feed_status_rows(
    rows: &mut Vec<ActivityFeedPaneRow>,
    session: &ActivitySession,
    route: &ActivityRouteState,
    running_tool: Option<&str>,
    width: usize,
) {
    prepend_feed_pause_row(rows, route);
    append_feed_placeholder_row(rows, session, route, running_tool);
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

fn stalled_progress_row(
    session: &ActivitySession,
    route: &ActivityRouteState,
    width: usize,
    running_tool: Option<&str>,
    now: Instant,
) -> Option<ActivityFeedPaneRow> {
    if route.paused || !activity_is_live(session, running_tool) {
        return None;
    }
    let (elapsed, source) = progress_silence_elapsed(session, now)?;
    if elapsed.as_secs() < STALLED_PROGRESS_AFTER_SECS {
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
                " ⚠ no progress signal for {} since {source}",
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

fn progress_silence_elapsed(
    session: &ActivitySession,
    now: Instant,
) -> Option<(Duration, &'static str)> {
    if let Some(observed_at) = session.last_run_item_at() {
        return now
            .checked_duration_since(observed_at)
            .map(|elapsed| (elapsed, "last lifecycle event"));
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
        Blocked => ActivityFeedRowTone::Warn,
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

fn wrapped_feed_rows(
    key: Option<kuzushi_core::run_lifecycle::RunCellKey>,
    disclosed_keys: BTreeSet<kuzushi_core::run_lifecycle::RunCellKey>,
    text: &str,
    width: usize,
    tone: ActivityFeedRowTone,
) -> Vec<ActivityFeedPaneRow> {
    let body_width = width.saturating_sub(1).max(1);
    let chunks = if display_width(text) <= body_width {
        vec![text.to_string()]
    } else {
        crate::renderer::shared::text::wrap_text(text, body_width)
    };
    chunks
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(accounted_feed_keys(&rows), presentation.semantic_keys());
        assert!(rows.iter().any(|row| row.text.contains("preview one")));
        assert!(rows
            .iter()
            .any(|row| row.text.contains("Indexing repository files · 421/832")));
        assert!(!rows.iter().any(|row| row.text.contains("preview two")));
        assert!(!rows.iter().any(|row| row.text.contains("Call ")));
        assert!(!rows.iter().any(|row| row.text.contains("HEALTH")));

        let mut route = ActivityRouteState::default();
        route.verbose_subsystems = true;
        let verbose = activity_feed_pane_rows(&session, &route, 180, None, Instant::now());
        assert!(verbose.iter().any(|row| row.text.contains("preview two")));
        assert!(verbose
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

        let mut route = ActivityRouteState::default();
        route.verbose_subsystems = true;
        let rows = activity_feed_pane_rows(&session, &route, 180, None, Instant::now());
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
        assert!(rows.iter().any(|row| row.text.contains("Asked operator")));
        assert!(rows
            .iter()
            .any(|row| row.text.contains("Operator decision recorded")));
        assert!(!rows
            .iter()
            .any(|row| row.text.contains("Waiting for operator input")));
        assert!(!rows.iter().any(|row| row.text.contains("Changed files")));
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

        let mut route = ActivityRouteState::default();
        route.verbose_subsystems = true;
        let rows = activity_feed_pane_rows(&session, &route, 180, None, Instant::now());
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
        let expected_omitted =
            presentation_timeline_len(&session).saturating_sub(LIVE_OUTPUT_EVENT_WINDOW);
        assert_eq!(omitted, expected_omitted);
        assert!(disclosure
            .text
            .contains(&format!("{omitted} timeline rows")));
        assert!(disclosure.text.contains("inspect trace/replay"));
        assert_eq!(accounted_feed_keys(&rows), expected);
    }

    #[test]
    fn narrow_typed_run_focus_wraps_without_losing_source_keys() {
        use kuzushi_core::run_lifecycle::{present_projection, RunProjectionSource};
        let mut session = typed_live_session();
        append_timeline_notices(&mut session, 1);
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
        assert!(rows
            .iter()
            .all(|row| crate::renderer::shared::text::display_width(&row.text) <= 24));
        assert!(rows.iter().any(|row| row.text.contains("比较候选路径")));
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

    fn presentation_timeline_len(session: &ActivitySession) -> usize {
        use kuzushi_core::run_lifecycle::{present_projection, RunProjectionSource};
        present_projection(&session.run_projection, RunProjectionSource::TypedV1)
            .timeline_text_rows()
            .len()
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
                    message: SafeText::operator_visible(format!("notice {index} · 比较候选路径")),
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
            "Run completed",
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
        push_live_call_progress(items, run_id, task_id, call_id, item_id);
        push_live_call_finish(items, run_id, task_id, call_id, item_id);
    }

    fn push_live_call_progress(
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
            RunItemV1::ToolCallProgress {
                message: SafeText::operator_visible("Indexing repository files"),
                completed: Some(421),
                total: Some(832),
            },
        );
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
}
