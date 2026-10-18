use super::*;
use crate::ui_view_models::{EngagementHeaderModel, JourneyPhaseStatus, WorkbenchHint};
use ratatui::style::Modifier;
use std::time::{SystemTime, UNIX_EPOCH};

pub(in crate::renderer::views) fn compact_review_header_lines(
    header: &EngagementHeaderModel,
    width: usize,
) -> Vec<Line<'static>> {
    let mut lines = vec![identity_line(header, width)];
    lines.extend(checkpoint_drift_line(header, width));
    lines.extend(
        header
            .finding_filter
            .as_deref()
            .map(|filter| finding_filter_line(filter, width)),
    );
    lines
}

pub(in crate::renderer::views) fn phase_header_lines(
    header: &EngagementHeaderModel,
    hints: &[WorkbenchHint],
    width: usize,
    height: usize,
) -> Vec<Line<'static>> {
    let mut lines = vec![identity_line(header, width)];
    lines.extend(context_header_lines(header, width));
    if header.phase == kuzushi_core::WorkflowPhase::Prove
        && header
            .result_card
            .as_ref()
            .is_some_and(|card| card.has_result_actions())
    {
        return lines;
    }
    let trailing = command_hint_lines(header, hints, width);
    let card_rows = height.saturating_sub(lines.len() + trailing.len() + 3);
    let card_rows = phase_result_header_budget(header.phase, card_rows);
    lines.extend(result_card_lines(
        header.result_card.as_ref(),
        width,
        card_rows,
    ));
    lines.extend(trailing);
    lines
}

fn phase_result_header_budget(phase: kuzushi_core::WorkflowPhase, rows: usize) -> usize {
    use kuzushi_core::WorkflowPhase;
    match phase {
        WorkflowPhase::Scan => rows.min(3),
        // Wrapped receipt identifiers and recovery text must not consume the
        // findings area. The full card remains available through Open.
        WorkflowPhase::Review if rows < 16 => rows.min(3),
        _ => rows,
    }
}

fn context_header_lines(header: &EngagementHeaderModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    lines.extend(checkpoint_drift_line(header, width));
    lines.extend(phase_rail_line(&header.phase_rail, width));
    lines.extend(
        header
            .finding_filter
            .as_deref()
            .map(|filter| finding_filter_line(filter, width)),
    );
    lines.extend(next_header_lines(header, width));
    lines
}

fn checkpoint_drift_line(header: &EngagementHeaderModel, width: usize) -> Option<Line<'static>> {
    let drift = header.checkpoint_drift.as_ref()?;
    let phase = drift.phase.title();
    let accepted = short_revision(drift.accepted_revision.as_deref());
    let current = short_revision(drift.current_revision.as_deref());
    let change = checkpoint_change_text(drift);
    let full = format!(
        "! accepted {phase} is stale · rev {accepted} → {current} · {change} · rerun {phase}"
    );
    let compact = format!("! {phase} stale · rerun {phase} · {accepted}→{current}");
    let minimal = format!("! {phase} stale · rerun {phase}");
    let text = if display_width(&full) <= width {
        full
    } else if display_width(&compact) <= width {
        compact
    } else {
        minimal
    };
    Some(Line::from(Span::styled(fit(&text, width), theme::warn())))
}

fn checkpoint_change_text(drift: &crate::ui_view_models::CheckpointDrift) -> String {
    let change = match drift.relationship {
        Some(kuzushi_core::workspace::RevisionRelationship::AheadBy(count)) => {
            let noun = if count == 1 { "commit" } else { "commits" };
            format!("{count} {noun} behind")
        }
        Some(kuzushi_core::workspace::RevisionRelationship::DivergedOrRewound) => {
            "history diverged or rewound".to_string()
        }
        Some(kuzushi_core::workspace::RevisionRelationship::Unavailable) => {
            "commit distance unavailable".to_string()
        }
        Some(kuzushi_core::workspace::RevisionRelationship::Same) if drift.dirty_changed => {
            "working tree changed".to_string()
        }
        Some(kuzushi_core::workspace::RevisionRelationship::Same) => {
            "checkpoint snapshot changed".to_string()
        }
        None if drift.accepted_revision != drift.current_revision => {
            "revision changed; checking distance".to_string()
        }
        None => "working tree changed".to_string(),
    };
    change
}

fn short_revision(revision: Option<&str>) -> String {
    revision
        .map(|revision| revision.chars().take(7).collect())
        .unwrap_or_else(|| "unknown".to_string())
}

fn next_header_lines(header: &EngagementHeaderModel, width: usize) -> Vec<Line<'static>> {
    if uses_compact_result_header(header, width) {
        return Vec::new();
    }
    next_lines(header, width)
}

fn command_hint_lines(
    header: &EngagementHeaderModel,
    hints: &[WorkbenchHint],
    width: usize,
) -> Vec<Line<'static>> {
    if header.result_card.is_some() || width < 80 || hints.is_empty() {
        return Vec::new();
    }
    vec![command_hint_line(hints, width)]
}

fn uses_compact_result_header(header: &EngagementHeaderModel, width: usize) -> bool {
    width < 50 && header.result_card.is_some()
}

fn result_card_lines(
    card: Option<&crate::ui_view_models::PhaseResultCardModel>,
    width: usize,
    max_rows: usize,
) -> Vec<Line<'static>> {
    let Some(card) = card else {
        return Vec::new();
    };
    result_card_render_rows(card, width, max_rows)
        .into_iter()
        .map(|row| {
            // Source identities intentionally terminate at this styling boundary.
            let _source_key = row.key;
            let _disclosed_source_keys = row.disclosed_keys;
            row.line
        })
        .collect()
}

#[derive(Debug)]
struct PhaseResultRenderRow {
    line: Line<'static>,
    key: Option<kuzushi_core::run_lifecycle::RunCellKey>,
    disclosed_keys: std::collections::BTreeSet<kuzushi_core::run_lifecycle::RunCellKey>,
}

#[derive(Debug, Default)]
struct PhaseResultRenderSource {
    key: Option<kuzushi_core::run_lifecycle::RunCellKey>,
    disclosed_keys: std::collections::BTreeSet<kuzushi_core::run_lifecycle::RunCellKey>,
}

#[derive(Debug, Clone, Copy)]
struct PhaseResultRenderStyle {
    prefix: ratatui::style::Style,
    text: ratatui::style::Style,
}

struct FixedPhaseResultRows {
    heading: Vec<PhaseResultRenderRow>,
    trailing: Vec<PhaseResultRenderRow>,
}

fn result_card_render_rows(
    card: &crate::ui_view_models::PhaseResultCardModel,
    width: usize,
    max_rows: usize,
) -> Vec<PhaseResultRenderRow> {
    if card.emphasis == crate::PhaseResultEmphasis::CompactDisposition {
        return compact_disposition_rows(card, width, max_rows);
    }
    if max_rows <= 3 {
        return compact_result_rows(card, width, max_rows);
    }
    let fixed = fixed_result_rows(card, width);
    let detail_budget = max_rows
        .saturating_sub(fixed.heading.len() + fixed.trailing.len())
        .max(1);
    let detail = bounded_result_detail_rows(card, width, detail_budget);
    fixed
        .heading
        .into_iter()
        .chain(detail)
        .chain(fixed.trailing)
        .collect()
}

fn compact_disposition_rows(
    card: &crate::ui_view_models::PhaseResultCardModel,
    width: usize,
    max_rows: usize,
) -> Vec<PhaseResultRenderRow> {
    if max_rows == 0 {
        return Vec::new();
    }
    let mut rows = vec![compact_result_row(
        " RESULT READY ",
        &card.compact_summary,
        width,
        theme::warn(),
        card.semantic_keys.clone(),
    )];
    if max_rows > 1 {
        rows.push(compact_result_row(
            "  ",
            &card.control_hint,
            width,
            theme::accent(),
            std::collections::BTreeSet::new(),
        ));
    }
    rows
}

fn compact_result_rows(
    card: &crate::ui_view_models::PhaseResultCardModel,
    width: usize,
    max_rows: usize,
) -> Vec<PhaseResultRenderRow> {
    if max_rows == 0 {
        return Vec::new();
    }
    let omitted = card.detail_rows.len();
    let summary = format!("{} · +{omitted} details · replay", card.outcome);
    vec![compact_result_row(
        " RESULT ",
        &summary,
        width,
        theme::warn(),
        card.semantic_keys.clone(),
    )]
}

fn compact_result_row(
    prefix: &str,
    text: &str,
    width: usize,
    style: ratatui::style::Style,
    disclosed_keys: std::collections::BTreeSet<kuzushi_core::run_lifecycle::RunCellKey>,
) -> PhaseResultRenderRow {
    let body_width = width.saturating_sub(display_width(prefix));
    PhaseResultRenderRow {
        line: Line::from(vec![
            Span::styled(prefix.to_string(), style),
            Span::styled(fit(text, body_width), style),
        ]),
        key: None,
        disclosed_keys,
    }
}

fn fixed_result_rows(
    card: &crate::ui_view_models::PhaseResultCardModel,
    width: usize,
) -> FixedPhaseResultRows {
    let heading = wrapped_result_row(
        " RESULT ",
        &format!("{} · attempt {}", card.outcome, card.attempt_id),
        width,
        PhaseResultRenderStyle {
            prefix: theme::warn(),
            text: theme::primary(),
        },
        PhaseResultRenderSource::default(),
    );
    let control = wrapped_result_row(
        "  ",
        &card.control_hint,
        width,
        PhaseResultRenderStyle {
            prefix: theme::accent(),
            text: theme::accent(),
        },
        PhaseResultRenderSource::default(),
    );
    let next = wrapped_result_row(
        "  next: ",
        &card.recommended,
        width,
        PhaseResultRenderStyle {
            prefix: theme::label(),
            text: theme::label(),
        },
        PhaseResultRenderSource::default(),
    );
    FixedPhaseResultRows {
        heading,
        trailing: control.into_iter().chain(next).collect(),
    }
}

fn bounded_result_detail_rows(
    card: &crate::ui_view_models::PhaseResultCardModel,
    width: usize,
    budget: usize,
) -> Vec<PhaseResultRenderRow> {
    let rows = card
        .detail_rows
        .iter()
        .flat_map(|row| {
            wrapped_result_row(
                "  ",
                &row.text,
                width,
                PhaseResultRenderStyle {
                    prefix: theme::muted(),
                    text: theme::muted(),
                },
                PhaseResultRenderSource {
                    key: row.key.clone(),
                    disclosed_keys: row.disclosed_keys.clone(),
                },
            )
        })
        .collect::<Vec<_>>();
    if rows.len() <= budget {
        return rows;
    }
    bounded_result_detail_overflow(rows, width, budget)
}

fn bounded_result_detail_overflow(
    rows: Vec<PhaseResultRenderRow>,
    width: usize,
    budget: usize,
) -> Vec<PhaseResultRenderRow> {
    let retained = retained_detail_count(rows.len(), width, budget);
    let omitted = rows.len().saturating_sub(retained);
    let disclosed_keys = accounted_render_keys(&rows[retained..]);
    let mut visible = rows.into_iter().take(retained).collect::<Vec<_>>();
    let disclosure = detail_disclosure_text(omitted, width);
    visible.extend(wrapped_result_row(
        "  ",
        &disclosure,
        width,
        PhaseResultRenderStyle {
            prefix: theme::warn(),
            text: theme::warn(),
        },
        PhaseResultRenderSource {
            key: None,
            disclosed_keys,
        },
    ));
    visible
}

fn retained_detail_count(total: usize, width: usize, budget: usize) -> usize {
    let mut retained = budget.saturating_sub(detail_disclosure_row_count(total, width));
    for _ in 0..2 {
        let omitted = total.saturating_sub(retained);
        retained = budget
            .saturating_sub(detail_disclosure_row_count(omitted, width))
            .min(total);
    }
    retained
}

fn detail_disclosure_row_count(omitted: usize, width: usize) -> usize {
    let body_width = width.saturating_sub(2).max(1);
    wrap_text(&detail_disclosure_text(omitted, width), body_width).len()
}

fn detail_disclosure_text(omitted: usize, width: usize) -> String {
    let detailed = format!("+{omitted} detail row(s) omitted · inspect/replay");
    if display_width(&detailed) <= width.saturating_sub(2) {
        return detailed;
    }
    format!("+{omitted} omitted · replay")
}

fn accounted_render_keys(
    rows: &[PhaseResultRenderRow],
) -> std::collections::BTreeSet<kuzushi_core::run_lifecycle::RunCellKey> {
    rows.iter()
        .flat_map(|row| row.key.iter().chain(row.disclosed_keys.iter()))
        .cloned()
        .collect()
}

fn wrapped_result_row(
    prefix: &str,
    text: &str,
    width: usize,
    style: PhaseResultRenderStyle,
    source: PhaseResultRenderSource,
) -> Vec<PhaseResultRenderRow> {
    let body_width = width.saturating_sub(display_width(prefix)).max(1);
    wrap_text(text, body_width)
        .into_iter()
        .enumerate()
        .map(|(index, chunk)| PhaseResultRenderRow {
            line: Line::from(vec![
                Span::styled(
                    if index == 0 {
                        prefix.to_string()
                    } else {
                        " ".repeat(display_width(prefix))
                    },
                    style.prefix,
                ),
                Span::styled(chunk, style.text),
            ]),
            key: source.key.clone(),
            disclosed_keys: source.disclosed_keys.clone(),
        })
        .collect()
}

fn finding_filter_line(filter: &str, width: usize) -> Line<'static> {
    Line::from(vec![
        Span::styled(" FILTER ", theme::warn()),
        Span::styled(
            fit(
                &format!("{filter} · clear: findings filter clear"),
                width.saturating_sub(8),
            ),
            theme::primary(),
        ),
    ])
}

fn identity_line(header: &EngagementHeaderModel, width: usize) -> Line<'static> {
    let mut spans = Vec::new();
    let mut used = 0;
    for atom in identity_atoms(header) {
        if !push_atom(&mut spans, &mut used, width, atom.text, atom.style) {
            if let Some(compact) = atom.compact {
                push_atom(&mut spans, &mut used, width, compact, atom.style);
            }
        }
    }
    Line::from(spans)
}

struct IdentityAtom {
    text: String,
    /// Narrower phrasing tried when the full text would evict the atom.
    /// Reality must survive at 40 columns; the viewed page lying about the
    /// pipeline's live phase is worse than terse wording.
    compact: Option<String>,
    style: ratatui::style::Style,
}

fn atom(text: String, style: ratatui::style::Style) -> IdentityAtom {
    IdentityAtom {
        text,
        compact: None,
        style,
    }
}

fn identity_atoms(header: &EngagementHeaderModel) -> Vec<IdentityAtom> {
    let mut atoms = vec![
        atom("KUZUSHI".to_string(), theme::heading()),
        atom(
            format!("Viewing {}", header.phase.title()),
            mode_style(header.phase),
        ),
    ];
    atoms.extend(reality_atom(header));
    let mut cost = cost_atom(header);
    if header.cost_invalid || !header.cost.is_complete() {
        atoms.extend(cost.take());
    }
    atoms.push(atom(format!("target {}", header.target), theme::label()));
    let (live_text, live_style) = live_atom(header.liveness);
    atoms.push(atom(live_text, live_style));
    atoms.extend(cost);
    atoms.push(atom(header.context.clone(), context_style(&header.context)));
    atoms.push(atom(format!("model {}", header.model), theme::muted()));
    atoms.extend(
        header
            .threat_model
            .as_ref()
            .map(|model| atom(model.clone(), theme::accent())),
    );
    atoms.push(atom(
        module_atom(&header.module),
        module_style(&header.module),
    ));
    atoms
}

fn reality_atom(header: &EngagementHeaderModel) -> Option<IdentityAtom> {
    let reality = header
        .reality_phase
        .filter(|reality| *reality != header.phase)?;
    Some(IdentityAtom {
        text: format!("next required {}", reality.title()),
        compact: Some(format!("next {}", reality.title())),
        style: theme::muted(),
    })
}

fn cost_atom(header: &EngagementHeaderModel) -> Option<IdentityAtom> {
    if header.cost_invalid {
        return Some(atom("cost accounting error".to_string(), theme::danger()));
    }
    if !header.cost.is_complete() {
        return Some(unmetered_cost_atom(header.cost));
    }
    (header.cost.observed_usd() > 0.0).then(|| {
        atom(
            format!(
                "cost {}",
                crate::ui_view_models::format_runtime_cost(header.cost, None)
            ),
            theme::primary(),
        )
    })
}

fn unmetered_cost_atom(cost: kuzushi_core::runtime::RuntimeCostReport) -> IdentityAtom {
    let text = if cost.is_unavailable() {
        "cost unknown (not recorded)".to_string()
    } else {
        format!(
            "cost {}",
            crate::ui_view_models::format_runtime_cost(cost, None)
        )
    };
    let compact = cost
        .estimated_total_usd()
        .filter(|_| cost.is_estimated())
        .map(|usd| format!("cost ~{}", crate::ui_view_models::format_session_cost(usd)))
        .unwrap_or_else(|| "cost unknown".to_string());
    IdentityAtom {
        text,
        compact: Some(compact),
        style: theme::warn(),
    }
}

fn mode_style(phase: kuzushi_core::WorkflowPhase) -> ratatui::style::Style {
    match phase {
        kuzushi_core::WorkflowPhase::Map => theme::mode_map(),
        kuzushi_core::WorkflowPhase::Scan => theme::mode_scan(),
        kuzushi_core::WorkflowPhase::Review => theme::mode_review(),
        kuzushi_core::WorkflowPhase::Prove => theme::mode_prove(),
        kuzushi_core::WorkflowPhase::Fix => theme::mode_fix(),
    }
}

fn module_atom(module: &str) -> String {
    if module == "all modules" {
        return "module all".to_string();
    }
    let module_id = module.split_once(':').map(|(id, _)| id).unwrap_or(module);
    format!("module {module_id}")
}

fn module_style(module: &str) -> ratatui::style::Style {
    if module == "all modules" {
        theme::muted()
    } else {
        theme::accent()
    }
}

fn context_style(context: &str) -> ratatui::style::Style {
    let normalized = context.to_ascii_lowercase();
    if normalized.contains("not built") || normalized.contains("missing") {
        theme::muted()
    } else if normalized.contains("stale") || normalized.contains("partial") {
        theme::warn()
    } else {
        theme::success()
    }
}

fn live_atom(liveness: crate::ui_view_models::WorkLiveness) -> (String, ratatui::style::Style) {
    match liveness {
        crate::ui_view_models::WorkLiveness::Idle => ("○ idle".to_string(), theme::subtle()),
        // External writers are updating workspace state — real activity the
        // badge must not report as idle, even though no local worker runs.
        crate::ui_view_models::WorkLiveness::ExternalSync => {
            ("◌ workspace sync".to_string(), theme::warn())
        }
        crate::ui_view_models::WorkLiveness::Live => {
            let mut style = theme::success();
            if live_pulse_on() {
                style = style.add_modifier(Modifier::BOLD);
            }
            ("● LIVE".to_string(), style)
        }
    }
}

fn live_pulse_on() -> bool {
    if !theme::cinematic_motion_enabled(theme::active_theme()) {
        return false;
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| (duration.as_millis() / 500) % 2 == 0)
        .unwrap_or(false)
}

fn push_atom(
    spans: &mut Vec<Span<'static>>,
    used: &mut usize,
    width: usize,
    text: String,
    style: ratatui::style::Style,
) -> bool {
    let separator_width = usize::from(*used > 0) * 3;
    let atom_width = display_width(&text);
    if used.saturating_add(separator_width + atom_width) > width {
        return false;
    }
    if *used > 0 {
        spans.push(Span::styled(" · ", theme::subtle()));
    }
    spans.push(Span::styled(text, style));
    *used += separator_width + atom_width;
    true
}

fn phase_rail_line(statuses: &[JourneyPhaseStatus], width: usize) -> Option<Line<'static>> {
    if statuses.is_empty() || width < 60 {
        return None;
    }
    let mut spans = vec![Span::raw(" ")];
    for (index, status) in statuses.iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled(" · ", theme::subtle()));
        }
        let style = journey_phase_tone_style(status.tone);
        spans.push(Span::styled(status.phase_label.to_string(), style));
        spans.push(Span::styled(status.navigation_symbol().to_string(), style));
    }
    spans.push(Span::styled(" · Report", theme::muted()));
    let line = Line::from(spans);
    (line.width() <= width).then_some(line)
}

fn next_lines(header: &EngagementHeaderModel, width: usize) -> Vec<Line<'static>> {
    let body = if width >= 100 || header.next_tools.is_empty() {
        header.next_action.clone()
    } else {
        header
            .next_action
            .split_once(" — ")
            .map(|(head, _)| head.to_string())
            .unwrap_or_else(|| header.next_action.clone())
    };
    wrap_text(&body, width.saturating_sub(8).max(16))
        .into_iter()
        .enumerate()
        .map(|(index, chunk)| {
            let lead = if index == 0 {
                Span::styled(" ▸ NEXT ", theme::warn())
            } else {
                Span::raw("        ")
            };
            Line::from(vec![lead, Span::styled(chunk, theme::primary())])
        })
        .collect()
}

fn command_hint_line(hints: &[WorkbenchHint], width: usize) -> Line<'static> {
    let mut spans = vec![Span::raw(" ")];
    let mut used = 1;
    for hint in hints {
        let atom = format!("{} {}", hint.verb, hint.label);
        let separator = usize::from(used > 1) * 3;
        let atom_width = display_width(&atom);
        if used + separator + atom_width > width {
            continue;
        }
        if separator > 0 {
            spans.push(Span::styled(" · ", theme::subtle()));
        }
        spans.push(Span::styled(atom, theme::muted()));
        used += separator + atom_width;
    }
    Line::from(spans)
}

#[cfg(test)]
mod tests;
