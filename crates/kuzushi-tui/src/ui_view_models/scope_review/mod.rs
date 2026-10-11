//! Pure scope-review projections. No workspace reads or dispatch policy.
mod detail;
use crate::app::{merge_destinations, ScopeReviewState, SCOPE_ACTIONS};
use crate::renderer::shared::text::wrap_text;
pub(crate) use detail::scope_detail;

pub(crate) fn scope_title(state: &ScopeReviewState) -> String {
    if state
        .form
        .as_ref()
        .is_some_and(|form| form.kind == crate::app::ScopeEditKind::AiPriorities)
    {
        return "AI SCOPE PRIORITIES".into();
    }
    state.review.as_ref().map_or_else(
        || "SCAN SCOPES".into(),
        |r| {
            format!(
                "{} SCOPES · r{}",
                if r.record.acceptance.is_some() {
                    "ACCEPTED"
                } else {
                    "DRAFT"
                },
                r.reference.revision
            )
        },
    )
}

fn scope_choice_rows(state: &ScopeReviewState) -> Option<(Vec<String>, usize)> {
    if let Some(index) = state.menu {
        return Some((SCOPE_ACTIONS.iter().map(|s| s.to_string()).collect(), index));
    }
    if let Some(index) = state.merge_target {
        return Some((
            merge_destinations(state)
                .iter()
                .map(|scope| scope.name.clone())
                .collect(),
            index,
        ));
    }
    if state.accepting {
        return Some((acceptance_rows(state), state.acknowledgement_cursor));
    }
    None
}

pub(crate) fn scope_rows(state: &ScopeReviewState) -> (Vec<String>, usize) {
    scope_choice_rows(state).unwrap_or_else(|| scope_boundary_rows(state))
}

fn scope_boundary_rows(state: &ScopeReviewState) -> (Vec<String>, usize) {
    let Some(review) = &state.review else {
        return (vec!["Build inventory [c]".into()], 0);
    };
    let draft = &review.record.draft;
    let mut rows = draft
        .scopes
        .iter()
        .map(|scope| marked_boundary_row(state, review, scope))
        .collect::<Vec<_>>();
    if let Some(shared) = &draft.shared_scope {
        rows.push(format!(
            "[{}] Shared: {} · {}",
            if state.study_scope_ids.contains(&shared.id) {
                "x"
            } else {
                " "
            },
            shared.name,
            if draft.shared_discovery {
                "discovery"
            } else {
                "context"
            }
        ));
    }
    rows.extend([
        format!("Uncovered · {}", review.coverage.uncovered_files.total),
        format!("Excluded · {}", review.coverage.excluded_files.total),
        format!("Overlap · {}", review.coverage.overlaps.total),
    ]);
    (rows, state.cursor)
}

fn marked_boundary_row(
    state: &ScopeReviewState,
    review: &kuzushi_core::workspace::ScanScopeReview,
    scope: &kuzushi_core::workspace::ProposedScanScope,
) -> String {
    let marker = if state.study_scope_ids.contains(&scope.id) {
        "x"
    } else {
        " "
    };
    format!("[{marker}] {}", scope_boundary_row(review, scope))
}

fn scope_boundary_row(
    review: &kuzushi_core::workspace::ScanScopeReview,
    scope: &kuzushi_core::workspace::ProposedScanScope,
) -> String {
    format!(
        "{} · {} files",
        scope.name,
        review
            .coverage
            .discovery_members
            .get(&scope.id)
            .map_or(0, |files| files.total)
    )
}

fn acceptance_rows(state: &ScopeReviewState) -> Vec<String> {
    let a = &state.acknowledgements;
    [
        (a.inventory_limitations, "Acknowledge inventory limits"),
        (a.overlapping_discovery, "Approve overlapping discovery"),
        (a.exclusions, "Acknowledge exclusions"),
    ]
    .into_iter()
    .map(|(selected, label)| format!("[{}] {label}", if selected { "x" } else { " " }))
    .chain(std::iter::once("Accept exact boundaries".into()))
    .collect()
}

pub(crate) fn scope_controls(state: &ScopeReviewState) -> [&'static str; 2] {
    if state.pending.is_some() {
        return ["Working · Ctrl+C cancel", "Esc back · draft preserved"];
    }
    if let Some(form) = &state.form {
        return scope_form_controls(form);
    }
    if state.accepting {
        return [
            "↑↓ choose · Enter toggle / accept",
            "PgUp/Dn read · Esc back",
        ];
    }
    scope_navigation_controls(state)
}

fn scope_form_controls(form: &crate::app::ScopeEditForm) -> [&'static str; 2] {
    if form.kind == crate::app::ScopeEditKind::AiPriorities {
        return [
            "F2 next · F3 context · Esc cancel",
            "Enter new line · arrows edit",
        ];
    }
    if form.fields.len() == 1 {
        return [
            "Enter / F2 save · arrows edit",
            "Esc cancel edit · draft preserved",
        ];
    }
    [
        "F2 save · Tab/Shift+Tab field",
        "Enter new line · Esc cancel edit",
    ]
}

fn scope_navigation_controls(state: &ScopeReviewState) -> [&'static str; 2] {
    if state.menu.is_some() || state.merge_target.is_some() {
        return ["↑↓ choose · Enter select", "Esc back · no scans start"];
    }
    if state.review.is_none() {
        return ["Enter / c build inventory", "Esc back · no model requests"];
    }
    if state.files.is_some() {
        return [
            "PgUp/Dn read · [ ] file pages",
            "↑↓ scope · Esc close files",
        ];
    }
    [
        "↑↓ Space mark · p plan · Enter menu",
        "f files · PgUp/Dn read · Esc back",
    ]
}

pub(crate) fn scope_detail_lines(state: &ScopeReviewState, width: usize) -> Vec<String> {
    let mut text = Vec::new();
    if let Some(notice) = &state.notice {
        text.extend([notice.clone(), String::new()]);
    }
    text.extend(scope_detail(state));
    text.into_iter()
        .flat_map(|line| wrap_text(&line, width.max(1)))
        .collect()
}

pub(crate) fn scope_layout(
    area: ratatui::layout::Rect,
    row_count: usize,
) -> super::study_config::StudyConfigLayout {
    let mut layout = super::study_config::study_config_layout(area);
    if layout.list.x == layout.detail.x {
        let height = layout.list.height.min(row_count.min(4) as u16);
        let released = layout.list.height - height;
        layout.list.height = height;
        layout.detail.y = layout.detail.y.saturating_sub(released);
        layout.detail.height += released;
    }
    layout
}
