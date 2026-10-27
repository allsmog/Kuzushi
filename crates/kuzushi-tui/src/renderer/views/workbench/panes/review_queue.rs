use super::*;
use crate::ui_view_models::{ReviewQueueModel, ReviewQueueRow, SeverityTone};
use kuzushi_core::ProofConfidence;
use ratatui::layout::Rect;
use ratatui::prelude::{Line, Span};

mod compact;

const REVIEW_FULL_SIGNAL_MIN_WIDTH: usize = 96;
const REVIEW_FULL_METADATA_MIN_WIDTH: usize = 96;

pub(in crate::renderer::views::workbench) fn review_queue_pane_lines(
    model: &ReviewQueueModel,
    inner: Rect,
) -> Vec<Line<'static>> {
    if model.rows.is_empty() {
        return review_queue_empty_lines(model, inner);
    }
    populated_review_queue_pane_lines(model, inner)
}

fn review_queue_empty_lines(model: &ReviewQueueModel, inner: Rect) -> Vec<Line<'static>> {
    if let Some(feedback) = &model.refresh_status {
        return review_read_feedback_lines(model, feedback, inner.width as usize);
    }
    let width = inner.width as usize;
    let reason = model
        .empty_reason
        .as_deref()
        .unwrap_or("no review rows match this mode");
    let mut lines = review_queue_chrome_lines(model, inner);
    lines.extend([
        Line::styled("∅ 0 matches", theme::muted()),
        Line::raw(fit(reason, width)),
        Line::styled(fit(&review_reset_hint(model), width), theme::accent()),
    ]);
    lines
}

fn review_read_feedback_lines(
    model: &ReviewQueueModel,
    feedback: &crate::ui_view_models::ReviewReadFeedback,
    width: usize,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    append_or_wrap(&mut lines, &feedback.message, width);
    for chip in &model.active_filter_chips {
        append_or_wrap(&mut lines, &format!("[{chip}]"), width);
    }
    for recovery in feedback.recovery_lines() {
        append_or_wrap(&mut lines, recovery, width);
    }
    lines.into_iter().map(Line::raw).collect()
}

fn populated_review_queue_pane_lines(model: &ReviewQueueModel, inner: Rect) -> Vec<Line<'static>> {
    if inner.width < 72 && inner.height != u16::MAX {
        return compact::lines(model, inner);
    }
    let width = inner.width as usize;
    let mut lines = review_queue_chrome_lines(model, inner);
    let viewport = review_queue_viewport(model, inner, lines.len());
    for (index, row) in model
        .rows
        .iter()
        .enumerate()
        .skip(viewport.start)
        .take(viewport.visible_findings)
    {
        let is_selected = Some(index) == viewport.selected;
        lines.push(review_queue_row_line_with_selection(
            row,
            width,
            is_selected,
        ));
        if is_selected {
            lines.extend(compact_selected_detail_lines(
                row,
                width,
                viewport.detail_rows,
                model.navigation_active,
            ));
        }
    }
    lines
}

struct ReviewQueueViewport {
    selected: Option<usize>,
    detail_rows: usize,
    visible_findings: usize,
    start: usize,
}

fn review_queue_chrome_lines(model: &ReviewQueueModel, inner: Rect) -> Vec<Line<'static>> {
    let width = inner.width as usize;
    let legend = if width >= 120 {
        "[●●●] runtime · [●●○] static · [●○○] signal · [×××] dismissed · s# sources · @H human · @A automated · @I imported · @– none · @? unknown"
    } else if width >= 72 {
        "bands named · s# count · @H/A/I/–/? author"
    } else {
        "s# count · @H human · @A auto · @I imported · @– none · @? unknown"
    };
    let mut summaries = active_filter_lines(model, width);
    if width >= 72 {
        append_or_wrap(&mut summaries, legend, width);
    }
    let mut lines = summaries
        .into_iter()
        .map(|summary| Line::styled(fit(&summary, width), theme::muted()))
        .collect::<Vec<_>>();
    lines.extend(review_facet_lines(model, inner));
    if width < 72 && inner.height >= 5 {
        lines.push(Line::styled(fit(legend, width), theme::muted()));
    }
    lines
}

fn active_filter_lines(model: &ReviewQueueModel, width: usize) -> Vec<String> {
    let mut lines = model
        .decision_save_label
        .iter()
        .map(|label| format!("Saving {label} · awaiting result"))
        .collect::<Vec<_>>();
    lines.extend(
        model
            .refresh_status
            .iter()
            .map(|feedback| feedback.message.clone()),
    );
    lines.extend(model.page.map(|page| page.label()));
    lines.push(match model.partial_load {
        Some(partial) => partial.label(),
        None => format!("{} of {}", model.visible_count, model.total_count),
    });
    lines.extend(
        model
            .path_history
            .then(|| "File paths across saved revisions".into()),
    );
    for chip in &model.active_filter_chips {
        append_or_wrap(&mut lines, &format!("[{chip}]"), width);
    }
    if let Some(indicator) = model.ordering_indicator {
        lines.push(format!("[{}]", ordering_label(indicator, width)));
    }
    if model.operator_calibration.is_available() {
        lines.push(model.operator_calibration.label(width < 72));
    }
    lines
}

fn ordering_label(indicator: &str, width: usize) -> &str {
    if width < 48 && indicator != crate::ui_view_models::LEARN_ORDERING_INDICATOR {
        return "order: proof > severity";
    }
    indicator
}

fn append_or_wrap(lines: &mut Vec<String>, value: &str, width: usize) {
    let separator = if lines.len() == 1 { " · " } else { " " };
    let Some(current) = lines.last_mut() else {
        lines.push(value.to_string());
        return;
    };
    if current.chars().count() + separator.chars().count() + value.chars().count() <= width {
        current.push_str(separator);
        current.push_str(value);
    } else {
        lines.push(value.to_string());
    }
}

fn review_facet_lines(model: &ReviewQueueModel, inner: Rect) -> Vec<Line<'static>> {
    let height = inner.height as usize;
    if height < 9 {
        return Vec::new();
    }
    let width = inner.width as usize;
    let groups = model
        .facet_groups
        .iter()
        .map(format_facet_group)
        .collect::<Vec<_>>();
    if height >= 12 {
        return groups
            .into_iter()
            .enumerate()
            .map(|(index, group)| {
                let prefix = if index == 0 {
                    "facets before search · "
                } else {
                    "  "
                };
                Line::styled(fit(&format!("{prefix}{group}"), width), theme::subtle())
            })
            .collect();
    }
    groups
        .chunks(2)
        .enumerate()
        .map(|(index, pair)| {
            let prefix = if index == 0 { "facets pre · " } else { "" };
            Line::styled(
                fit(&format!("{prefix}{}", pair.join(" · ")), width),
                theme::subtle(),
            )
        })
        .collect()
}

fn format_facet_group(group: &crate::ui_view_models::ReviewFacetGroup) -> String {
    if group.values.is_empty() {
        return format!("{}:0", group.label);
    }
    let visible = group
        .values
        .iter()
        .take(3)
        .map(|value| format!("{}:{}", value.value, value.count))
        .collect::<Vec<_>>()
        .join(" ");
    let overflow = group.values.len().saturating_sub(3);
    if overflow == 0 {
        format!("{} {visible}", group.label)
    } else {
        format!("{} {visible} +{overflow}", group.label)
    }
}

fn review_reset_hint(model: &ReviewQueueModel) -> String {
    if model.search_capture {
        return "Reset: Esc clears search · `findings` clears loaded filters".to_string();
    }
    if model.search_active {
        return "Reset: / then Esc clears search · `findings` clears loaded filters".to_string();
    }
    "Reset: `findings` clears loaded filters".to_string()
}

fn review_queue_viewport(
    model: &ReviewQueueModel,
    inner: Rect,
    chrome_rows: usize,
) -> ReviewQueueViewport {
    let width = inner.width as usize;
    let visible = (inner.height as usize).saturating_sub(chrome_rows).max(1);
    let selected = model
        .selected_row
        .or_else(|| model.rows.iter().position(|row| row.selected));
    let detail_rows = compact_selected_detail_budget(width, visible, selected.is_some());
    let visible_findings = visible.saturating_sub(detail_rows).max(1);
    let cursor = selected.unwrap_or(0);
    ReviewQueueViewport {
        selected,
        detail_rows,
        visible_findings,
        start: viewport_start_for_cursor(model.rows.len(), visible_findings, cursor),
    }
}

fn compact_selected_detail_budget(width: usize, visible: usize, has_selection: bool) -> usize {
    if width >= 72 || !has_selection {
        return 0;
    }
    visible.saturating_sub(1).min(3)
}

fn compact_selected_detail_lines(
    row: &ReviewQueueRow,
    width: usize,
    budget: usize,
    navigation_active: bool,
) -> Vec<Line<'static>> {
    let open_hint = if navigation_active {
        "Enter open"
    } else {
        "Esc nav, then Enter open"
    };
    let action = Line::styled(
        fit(
            &format!("  ▸ next:{} · {open_hint}", row.next_action),
            width,
        ),
        theme::warn(),
    );
    if budget == 0 {
        return Vec::new();
    }
    if budget == 1 {
        return vec![action];
    }
    let location = Line::styled(
        format!(
            "  {}",
            fit_location_label(&row.location, width.saturating_sub(2))
        ),
        theme::muted(),
    );
    if budget == 2 {
        return vec![location, action];
    }
    vec![
        Line::styled(fit(&format!("  {}", row.title), width), theme::primary()),
        location,
        action,
    ]
}

#[cfg(test)]
fn review_queue_row_line(row: &ReviewQueueRow, width: usize) -> Line<'static> {
    review_queue_row_line_with_selection(row, width, row.selected)
}

fn review_queue_row_line_with_selection(
    row: &ReviewQueueRow,
    width: usize,
    selected: bool,
) -> Line<'static> {
    let signals = review_queue_signal_text(row, width);
    let signals_width = review_queue_signal_width(width);
    let chip = review_queue_metadata_chip(row, width);
    let title_budget = review_queue_title_budget(width, signals_width, chip.chars().count());
    if selected {
        return selected_review_queue_row(row, width, &signals, signals_width, &chip, title_budget);
    }
    Line::from(vec![
        Span::styled(" ", theme::muted()),
        Span::styled(
            pad(&row.alias, 7),
            review_queue_row_style(theme::label(), selected),
        ),
        Span::raw(" "),
        Span::styled(
            severity_glyph(row.severity_tone),
            review_queue_row_style(theme::severity_tone(row.severity_tone), selected),
        ),
        Span::raw(" "),
        Span::styled(
            chip,
            review_queue_row_style(theme::proof_confidence_tone(row.proof_confidence), selected),
        ),
        Span::raw(" "),
        Span::styled(
            pad(&signals, signals_width),
            review_queue_row_style(review_queue_decision_style(row), selected),
        ),
        Span::raw(" "),
        Span::styled(
            fit(&review_queue_title_text(row, width), title_budget),
            review_queue_row_style(theme::primary(), selected),
        ),
    ])
}

fn review_queue_metadata_chip(row: &ReviewQueueRow, width: usize) -> String {
    let confidence = review_queue_confidence_chip(row, width);
    let Some(occurrence) = row.occurrence else {
        return confidence;
    };
    let occurrence = if width < REVIEW_FULL_METADATA_MIN_WIDTH {
        format!("occ {}/{}", occurrence.seen, occurrence.completed)
    } else {
        format!(
            "occ {}/{} p{} f{}",
            occurrence.seen, occurrence.completed, occurrence.planned, occurrence.failed
        )
    };
    format!("{confidence} {occurrence}")
}

fn selected_review_queue_row(
    row: &ReviewQueueRow,
    width: usize,
    signals: &str,
    signals_width: usize,
    chip: &str,
    title_budget: usize,
) -> Line<'static> {
    let body = format!(
        "▸{} {} {} {} {}",
        pad(&row.alias, 7),
        severity_glyph(row.severity_tone),
        chip,
        pad(signals, signals_width),
        fit(&review_queue_title_text(row, width), title_budget),
    );
    Line::styled(pad(&fit(&body, width), width), theme::selection())
}

/// The confidence chip that sits between the severity glyph and the decision
/// signals. The full evidence label appears at readable widths; compact widths
/// use a plain-language evidence source while the adjacent legend explains the
/// meter, source count, and decision-author markers.
fn review_queue_confidence_chip(row: &ReviewQueueRow, width: usize) -> String {
    let confidence = if width < REVIEW_FULL_METADATA_MIN_WIDTH {
        compact_proof_confidence_label(row)
    } else {
        row.proof_confidence_label.as_str()
    };
    format!(
        "{} s{} {} {confidence}",
        row.proof_meter,
        row.source_count,
        authority_marker(row)
    )
}

fn authority_marker(row: &ReviewQueueRow) -> &'static str {
    match row.decision_author.as_str() {
        "human" | "operator" => "@H",
        "auto" | "agent" | "model" => "@A",
        "imported" => "@I",
        "-" => "@–",
        _ => "@?",
    }
}

fn compact_proof_confidence_label(row: &ReviewQueueRow) -> &str {
    match row.proof_confidence {
        ProofConfidence::Confirmed => "runtime",
        ProofConfidence::Likely => "static",
        ProofConfidence::Unverified => "signal",
        ProofConfidence::Dismissed => row.proof_confidence_label.as_str(),
    }
}

fn review_queue_signal_text(row: &ReviewQueueRow, width: usize) -> String {
    if width < REVIEW_FULL_SIGNAL_MIN_WIDTH {
        return review_queue_compact_decision(row).to_string();
    }
    fit(
        &review_queue_full_signal_summary(row),
        review_queue_signal_width(width),
    )
}

fn review_queue_signal_width(width: usize) -> usize {
    if width < REVIEW_FULL_SIGNAL_MIN_WIDTH {
        if width < 48 {
            4
        } else {
            10
        }
    } else if width >= REVIEW_FULL_METADATA_MIN_WIDTH {
        width.saturating_sub(72).clamp(32, 120)
    } else {
        width.saturating_sub(38).clamp(58, 112)
    }
}

fn review_queue_title_budget(width: usize, signal_width: usize, chip_width: usize) -> usize {
    let prefix_width = 2 + 7 + 1 + 1 + 1 + chip_width + 1 + signal_width + 1;
    width.saturating_sub(prefix_width)
}

fn review_queue_title_text(row: &ReviewQueueRow, width: usize) -> String {
    if width < REVIEW_FULL_METADATA_MIN_WIDTH {
        return row.title.clone();
    }
    format!("{} · {}", row.title, row.location)
}

fn review_queue_full_signal_summary(row: &ReviewQueueRow) -> String {
    format!(
        "{} {} decision:{}{} {} next:{} status:{} decision-score:{}",
        row.identity_label,
        row.priority_label,
        review_queue_decision_label(row),
        review_queue_conflict_segment(row),
        row.evidence_state,
        row.next_action,
        row.lifecycle_status,
        row.confidence_label
    )
}

fn review_queue_conflict_segment(row: &ReviewQueueRow) -> String {
    row.decision_conflict
        .as_ref()
        .map(|conflict| {
            format!(
                " {}:{}",
                crate::ui_view_models::review_conflicts::review_conflict_status_label(conflict),
                crate::ui_view_models::review_conflicts::review_conflict_compact_label(conflict)
            )
        })
        .unwrap_or_default()
}

fn review_queue_decision_label(row: &ReviewQueueRow) -> &str {
    if row.decision_conflict.is_some() && row.decision == "rejected_false_positive" {
        return "rejected_fp";
    }
    &row.decision
}

fn review_queue_compact_decision(row: &ReviewQueueRow) -> &'static str {
    if let Some(conflict) = row.decision_conflict.as_deref() {
        return crate::ui_view_models::review_conflicts::review_conflict_status_label(conflict);
    }
    compact_review_verdict(&row.decision)
}

fn compact_review_verdict(decision: &str) -> &'static str {
    if decision.ends_with(" · reassess") {
        return "reassess";
    }
    [
        ("confirmed", "confirmed"),
        ("rejected_false_positive", "false-pos"),
        ("false_positive", "false-pos"),
        ("suppressed", "suppressed"),
        ("deferred", "deferred"),
        ("accepted_risk", "risk"),
    ]
    .into_iter()
    .find_map(|(verdict, label)| (verdict == decision).then_some(label))
    .unwrap_or("open")
}

fn review_queue_decision_style(row: &ReviewQueueRow) -> ratatui::style::Style {
    if row.decision_conflict.is_some() {
        return theme::warn();
    }
    match row.decision.as_str() {
        "confirmed" => theme::success(),
        "rejected_false_positive" | "false_positive" | "suppressed" => theme::accent(),
        "deferred" | "accepted_risk" => theme::warn(),
        _ => theme::muted(),
    }
}

fn review_queue_row_style(
    fallback: ratatui::style::Style,
    selected: bool,
) -> ratatui::style::Style {
    if selected {
        theme::selection()
    } else {
        fallback
    }
}

fn severity_glyph(tone: SeverityTone) -> &'static str {
    match tone {
        SeverityTone::Critical => "C",
        SeverityTone::High => "H",
        SeverityTone::Medium => "M",
        SeverityTone::Low => "L",
        SeverityTone::Info => "I",
        SeverityTone::Unknown => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui_view_models::ReviewWorkflowGroup;

    mod compact_reading;

    fn review_row() -> ReviewQueueRow {
        ReviewQueueRow {
            alias: "F-0001".to_string(),
            identity_label: "FI-12345678".to_string(),
            severity_tone: SeverityTone::High,
            severity_label: "HIGH".to_string(),
            proof_confidence: ProofConfidence::Confirmed,
            proof_confidence_label: "RUNTIME VERIFIED".to_string(),
            confidence_label: "91%".to_string(),
            occurrence: None,
            priority_label: "review-order:1".to_string(),
            lifecycle_status: "statically_supported".to_string(),
            decision: "needs_review".to_string(),
            decision_conflict: None,
            decision_complete: false,
            decision_author: "unknown".to_string(),
            title: "request reaches sink".to_string(),
            location: "crates/kuzushi-tui/src/app/example.rs:42".to_string(),
            rule: "CWE-89".to_string(),
            tool: "semgrep".to_string(),
            proof_label: "source_sink_linked".to_string(),
            proof_meter: "[●●○]".to_string(),
            source_count: 2,
            evidence_state: "evidence:1".to_string(),
            next_action: "validate".to_string(),
            projection_index: 0,
            selected: true,
            workflow_group: ReviewWorkflowGroup::NeedsReview,
        }
    }

    fn grouped_row(alias: &str, group: ReviewWorkflowGroup, selected: bool) -> ReviewQueueRow {
        let mut row = review_row();
        row.alias = alias.to_string();
        row.workflow_group = group;
        row.selected = selected;
        row
    }

    fn review_model(rows: Vec<ReviewQueueRow>) -> ReviewQueueModel {
        let selected_row = rows.iter().position(|row| row.selected);
        ReviewQueueModel {
            path_history: false,
            navigation_active: true,
            refresh_status: None,
            decision_save_label: None,
            page: None,
            partial_load: None,
            total_count: rows.len(),
            visible_count: rows.len(),
            open_count: rows.len(),
            complete_count: 0,
            search_active: false,
            search_capture: false,
            active_filter_chips: vec!["completeness:all".to_string()],
            facet_groups: Vec::new().into(),
            filter_label: "completeness:all".to_string(),
            completeness_mode: "all",
            ordering_indicator: None,
            operator_calibration: Default::default(),
            header: format!("REVIEW QUEUE - showing {} of {}", rows.len(), rows.len()),
            empty_reason: None,
            rows: rows.into(),
            selected_row,
        }
    }

    #[test]
    fn unavailable_study_is_not_zero_matches_and_wraps_both_recovery_actions() {
        for width in [40, 60, 80, 96, 120, 160] {
            let mut model = review_model(vec![]);
            model.refresh_status = Some(crate::ui_view_models::ReviewReadFeedback::failed(true));
            model.active_filter_chips = vec!["batch:owned-study".into()];
            let lines = review_queue_pane_lines(&model, Rect::new(0, 0, width, 30));
            assert!(lines.iter().all(|line| line.width() <= usize::from(width)));
            let text = lines_text(lines);
            for expected in [
                "scope retained",
                "batch:owned-study",
                "findings refresh",
                "batch clear",
            ] {
                assert!(text.contains(expected), "{width}: {text}");
            }
            assert!(!text.contains("0 matches"), "{text}");
            assert!(!text.contains("0 of 0"), "{text}");
            assert!(!text.contains("previous results"), "{text}");
            assert_eq!(model.population_title(), "FINDINGS · study unavailable");
        }
    }

    fn line_text(line: Line<'static>) -> String {
        line.spans
            .into_iter()
            .map(|span| span.content.into_owned())
            .collect::<String>()
    }

    fn lines_text(lines: Vec<Line<'static>>) -> String {
        lines
            .into_iter()
            .map(line_text)
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn row_names_decision_evidence_and_next_action() {
        let row = review_row();
        let text = line_text(review_queue_row_line(&row, 140));
        let wide_text = line_text(review_queue_row_line(&row, 220));

        assert!(text.contains("F-0001"), "{text}");
        assert!(text.contains("FI-12345678"), "{text}");
        assert!(
            wide_text.contains("status:statically_supported"),
            "{wide_text}"
        );
        assert!(text.contains("decision:needs_review"), "{text}");
        assert!(text.contains("evidence:1"), "{text}");
        assert!(wide_text.contains("next:validate"), "{wide_text}");
        assert!(text.contains("request reaches sink"), "{text}");
    }

    #[test]
    fn row_shows_confidence_chip_after_severity_glyph() {
        let row = review_row();
        let wide = line_text(review_queue_row_line(&row, 220));
        // At metadata widths the full band word sits right after the severity glyph.
        assert!(wide.contains("RUNTIME VERIFIED"), "{wide}");
        assert!(wide.contains("H [●●○] s2 @? RUNTIME VERIFIED"), "{wide}");
    }

    #[test]
    fn batch_row_has_a_visible_occurrence_column() {
        let mut row = review_row();
        row.occurrence = Some(crate::ui_view_models::ReviewOccurrence {
            seen: 2,
            completed: 3,
            planned: 4,
            failed: 1,
        });

        let narrow = line_text(review_queue_row_line(&row, 80));
        let wide = line_text(review_queue_row_line(&row, 220));

        assert!(narrow.contains("occ 2/3"), "{narrow}");
        assert!(wide.contains("occ 2/3 p4 f1"), "{wide}");
    }

    #[test]
    fn row_uses_plain_language_confidence_when_narrow() {
        let row = review_row();
        let narrow = line_text(review_queue_row_line(&row, 60));
        assert!(!narrow.contains("RUNTIME VERIFIED"), "{narrow}");
        assert!(narrow.contains("[●●○] s2 @? runtime"), "{narrow}");
        assert!(narrow.contains("open"), "{narrow}");
        assert!(!narrow.contains("review-order"), "{narrow}");
        assert!(!narrow.contains('✓'), "{narrow}");
    }

    #[test]
    fn every_row_discloses_human_decision_authority() {
        let mut row = review_row();
        row.decision_author = "human".to_string();

        let narrow = line_text(review_queue_row_line(&row, 48));
        let wide = line_text(review_queue_row_line(&row, 220));

        assert!(narrow.contains("@H"), "{narrow}");
        assert!(wide.contains("@H"), "{wide}");
    }

    #[test]
    fn no_decision_and_unknown_author_have_distinct_markers() {
        let mut row = review_row();
        row.decision_author = "-".to_string();
        assert!(line_text(review_queue_row_line(&row, 80)).contains("@–"));

        row.decision_author = "unexpected".to_string();
        assert!(line_text(review_queue_row_line(&row, 80)).contains("@?"));
    }

    #[test]
    fn compact_queue_names_evidence_and_source_count() {
        let text = lines_text(populated_review_queue_pane_lines(
            &review_model(vec![review_row()]),
            Rect::new(0, 0, 60, 6),
        ));

        assert!(text.contains("sources:2"), "{text}");
        assert!(text.contains("runtime verified"), "{text}");
        assert!(text.contains("@?"), "{text}");
    }

    #[test]
    fn tiny_queue_keeps_source_count_beside_finding_identity() {
        let text = lines_text(populated_review_queue_pane_lines(
            &review_model(vec![review_row()]),
            Rect::new(0, 0, 40, 3),
        ));
        assert!(text.contains("F-0001"), "{text}");
        assert!(text.contains("runtime verified s2"), "{text}");
    }

    #[test]
    fn row_names_a_decision_from_another_observation() {
        let mut row = review_row();
        row.proof_confidence = ProofConfidence::Unverified;
        row.proof_confidence_label = "UNVERIFIED".into();
        row.decision = "rejected_false_positive".to_string();
        row.decision_conflict = Some("reappeared_after_rejection".to_string());

        let text = line_text(review_queue_row_line(&row, 160));

        assert!(text.contains("decision:rejected_fp"), "{text}");
        assert!(text.contains("check source:other-observation"), "{text}");
        assert!(!text.contains("conflict:"), "{text}");
        assert_eq!(review_queue_compact_decision(&row), "check source");
    }

    #[test]
    fn genuine_proof_conflicts_keep_their_distinct_warning() {
        let mut row = review_row();
        for (conflict, decision) in [
            (
                "runtime_verified_after_rejection",
                "rejected_false_positive",
            ),
            ("not_reproduced_after_confirmation", "confirmed"),
        ] {
            row.decision = decision.into();
            row.decision_conflict = Some(conflict.into());
            assert_eq!(review_queue_compact_decision(&row), "conflict");
            let text = line_text(review_queue_row_line(&row, 160));
            assert!(text.contains("conflict:"), "{text}");
        }
    }

    #[test]
    fn display_preserves_canonical_row_order_without_workflow_headers() {
        let model = review_model(vec![
            grouped_row("F-0001", ReviewWorkflowGroup::Closed, false),
            grouped_row("F-0002", ReviewWorkflowGroup::NeedsReview, true),
            grouped_row("F-0003", ReviewWorkflowGroup::Deferred, false),
            grouped_row("F-0004", ReviewWorkflowGroup::NeedsReview, false),
            grouped_row("F-0005", ReviewWorkflowGroup::Confirmed, false),
        ]);

        let joined = lines_text(populated_review_queue_pane_lines(
            &model,
            Rect::new(0, 0, 120, 14),
        ));
        let positions = ["F-0001", "F-0002", "F-0003", "F-0004", "F-0005"]
            .map(|label| joined.find(label).expect("projected row rendered"));

        assert!(
            positions.windows(2).all(|pair| pair[0] < pair[1]),
            "{joined}"
        );
        assert!(joined.contains("▸F-0002"), "{joined}");
        assert_eq!(joined.matches('▸').count(), 1, "{joined}");
        assert!(!joined.contains("NEEDS REVIEW ·"), "{joined}");
        assert!(!joined.contains("CONFIRMED ·"), "{joined}");
        assert!(!joined.contains("DEFERRED ·"), "{joined}");
        assert!(!joined.contains("CLOSED ·"), "{joined}");
    }

    #[test]
    fn viewport_tracks_selected_finding_in_the_canonical_row_list() {
        let model = review_model(vec![
            grouped_row("F-0001", ReviewWorkflowGroup::NeedsReview, false),
            grouped_row("F-0002", ReviewWorkflowGroup::NeedsReview, false),
            grouped_row("F-0003", ReviewWorkflowGroup::Confirmed, true),
            grouped_row("F-0004", ReviewWorkflowGroup::Deferred, false),
            grouped_row("F-0005", ReviewWorkflowGroup::Closed, false),
        ]);

        let text = lines_text(populated_review_queue_pane_lines(
            &model,
            Rect::new(0, 0, 80, 5),
        ));
        assert!(text.contains("▸F-0003"), "{text}");
        assert!(text.contains("F-0004"), "{text}");
        assert!(text.contains("F-0005"), "{text}");
        assert_eq!(text.matches('▸').count(), 1, "{text}");
    }

    #[test]
    fn compact_viewport_keeps_moved_identity_title_and_location_visible() {
        for selected_index in [3, 7] {
            let rows = (0..8)
                .map(|index| {
                    grouped_row(
                        &format!("F-{:04}", index + 1),
                        ReviewWorkflowGroup::NeedsReview,
                        index == selected_index,
                    )
                })
                .collect();
            let text = lines_text(populated_review_queue_pane_lines(
                &review_model(rows),
                Rect::new(0, 0, 33, 6),
            ));
            let alias = format!("F-{:04}", selected_index + 1);

            assert!(text.contains(&format!("▸{alias}")), "{text}");
            assert!(text.contains("request reaches sink"), "{text}");
            assert!(text.contains("example.rs:42"), "{text}");
            assert!(text.contains("sources:2"), "{text}");
            assert!(text.lines().count() <= 6, "{text}");
        }
    }

    #[test]
    fn compact_viewport_keeps_active_filter_visible() {
        let mut model = review_model(vec![review_row()]);
        model.filter_label = "severity:high".to_string();
        model.active_filter_chips = vec!["severity:high".to_string()];

        let text = lines_text(populated_review_queue_pane_lines(
            &model,
            Rect::new(0, 0, 33, 6),
        ));

        assert!(text.contains("[severity:high]"), "{text}");
    }

    /// The ordering chip renders as its own bracketed line: what ordered the
    /// list is a different claim from what narrowed it, and a chip sharing a
    /// clipped line with a filter would read as a filter.
    #[test]
    fn the_ordering_indicator_renders_on_its_own_chip_line() {
        let mut model = review_model(vec![review_row()]);
        model.active_filter_chips = vec!["severity:high".to_string()];
        model.ordering_indicator = Some(crate::ui_view_models::LEARN_ORDERING_INDICATOR);

        let text = lines_text(populated_review_queue_pane_lines(
            &model,
            Rect::new(0, 0, 120, 12),
        ));

        let chip = format!("[{}]", crate::ui_view_models::LEARN_ORDERING_INDICATOR);
        let line = text
            .lines()
            .find(|line| line.contains(&chip))
            .unwrap_or_else(|| panic!("no ordering chip line in:\n{text}"));
        assert!(!line.contains("severity:high"), "{line}");
    }

    /// Absent by default: an ordering nobody asked for must leave no trace on
    /// the pane.
    #[test]
    fn no_ordering_indicator_renders_without_one() {
        let text = lines_text(populated_review_queue_pane_lines(
            &review_model(vec![review_row()]),
            Rect::new(0, 0, 120, 12),
        ));

        assert!(!text.contains("knowledge-gap"), "{text}");
    }

    #[test]
    fn compact_prompt_mode_does_not_claim_enter_is_immediately_active() {
        let mut model = review_model(vec![review_row()]);
        model.navigation_active = false;

        let text = lines_text(populated_review_queue_pane_lines(
            &model,
            Rect::new(0, 0, 48, 6),
        ));

        assert!(!text.contains("Enter"), "{text}");
    }

    #[test]
    fn empty_state_says_only_queue_is_empty() {
        let model = ReviewQueueModel {
            path_history: false,
            navigation_active: true,
            refresh_status: None,
            decision_save_label: None,
            page: None,
            partial_load: None,
            total_count: 2,
            visible_count: 0,
            open_count: 0,
            complete_count: 2,
            search_active: false,
            search_capture: false,
            active_filter_chips: vec!["completeness:open".to_string()],
            facet_groups: Vec::new().into(),
            filter_label: "completeness:open".to_string(),
            completeness_mode: "open",
            ordering_indicator: None,
            operator_calibration: Default::default(),
            header: "REVIEW QUEUE - showing 0 of 2 - 0 open - 2 complete".to_string(),
            empty_reason: Some("all visible findings have terminal decisions".to_string()),
            rows: Vec::new().into(),
            selected_row: None,
        };

        let text = lines_text(review_queue_empty_lines(&model, Rect::new(0, 0, 80, 8)));

        assert!(text.contains("0 matches"), "{text}");
        assert!(
            text.contains("all visible findings have terminal decisions"),
            "{text}"
        );
        assert!(text.contains("[completeness:open]"), "{text}");
    }

    #[test]
    fn linked_path_history_remains_visible_in_compact_queues() {
        let mut model = review_model(vec![review_row()]);
        model.path_history = true;
        model.active_filter_chips =
            vec![r#"files:["app/a  b.rs","app/long/source/name.rs"]"#.into()];
        for width in [40, 60, 80, 120] {
            let text = lines_text(populated_review_queue_pane_lines(
                &model,
                Rect::new(0, 0, width, 7),
            ));
            assert!(text.contains("saved revisions"), "{width}: {text}");
        }
    }

    #[test]
    fn zero_search_result_names_filters_and_exact_reset_path() {
        let mut model = review_model(Vec::new());
        model.total_count = 7;
        model.search_active = true;
        model.active_filter_chips = vec!["text:\"nope\"".to_string(), "status:open".to_string()];
        model.empty_reason = Some("no findings match the active search and filters".to_string());

        let text = lines_text(review_queue_empty_lines(&model, Rect::new(0, 0, 60, 8)));

        assert!(text.contains("0 of 7"), "{text}");
        assert!(text.contains("[text:\"nope\"]"), "{text}");
        assert!(text.contains("[status:open]"), "{text}");
        assert!(text.contains("no findings match"), "{text}");
        assert!(text.contains("/ then Esc clears search"), "{text}");
    }
}
