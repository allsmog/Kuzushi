//! Pure scope-review projections. No workspace reads or dispatch policy.
mod action_search;
mod detail;
pub(crate) use action_search::scope_search_label;
mod context;
mod recorded_context;
mod source;
mod tree;
mod workload;
use crate::app::{merge_destinations, ScopeReviewState, SCOPE_ACTIONS};
use crate::renderer::shared::text::wrap_text;
pub(crate) use detail::scope_detail;
pub(crate) use source::{scope_source_view, ScopeSourceView};

pub(crate) fn scope_title(state: &ScopeReviewState, source: &ScopeSourceView) -> String {
    if let Some(title) = state.form.as_ref().and_then(form_title) {
        return title.into();
    }
    if state.menu.is_some() {
        return scope_action_title(state).into();
    }
    state.review.as_ref().map_or_else(
        || "SCAN SCOPES".into(),
        |review| saved_scope_title(review, source),
    )
}

fn scope_action_title(state: &ScopeReviewState) -> &'static str {
    if state.selected_file().is_some() {
        "FILE ACTIONS"
    } else {
        "SCOPE ACTIONS"
    }
}

fn saved_scope_title(
    review: &kuzushi_core::workspace::ScanScopeReview,
    source: &ScopeSourceView,
) -> String {
    let label = match (
        source.unbound(),
        source.differs(),
        review.record.acceptance.is_some(),
    ) {
        (true, _, _) => "MEMBERSHIP UNBOUND · SCOPES",
        (false, true, _) => "SHA DIFFERS · SCOPES",
        (false, false, true) => "ACCEPTED SCOPES",
        _ => "DRAFT SCOPES",
    };
    let total = workload::all_jobs(review)
        .map(|jobs| format!("all: {jobs} jobs"))
        .unwrap_or_else(|_| "workload unavailable".into());
    format!("{label} · r{} · {total}", review.reference.revision)
}

fn form_title(form: &crate::app::ScopeEditForm) -> Option<&'static str> {
    match form.kind {
        crate::app::ScopeEditKind::AiPriorities => Some("AI SCOPE PRIORITIES"),
        crate::app::ScopeEditKind::Add => Some("ADD DISCOVERY SCOPE"),
        _ => None,
    }
}

fn scope_choice_rows(state: &ScopeReviewState) -> Option<(Vec<String>, usize)> {
    if let Some(index) = state.menu {
        return Some(action_search::action_rows(state, index));
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
    let rows = state
        .tree_rows()
        .iter()
        .map(|row| tree::row_label(state, review, row))
        .collect();
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
    let count = review
        .coverage
        .discovery_members
        .get(&scope.id)
        .map_or(0, |files| files.total);
    format!(
        "{} · {count} {}",
        scope.name,
        if count == 1 { "file" } else { "files" }
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
    if let Some(controls) = action_search::choice_controls(state) {
        return controls;
    }
    if state.review.is_none() {
        return ["Enter / c build inventory", "Esc back · no model requests"];
    }
    if state.files.is_some() {
        return [
            "PgUp/Dn read · [ ] file pages",
            "Home/End first/last · Esc back",
        ];
    }
    [
        "↑↓ →/← tree · Space mark · p plan",
        "Enter menu · f files · Esc back",
    ]
}

pub(crate) fn scope_detail_lines(
    app: &crate::app::ShellApp,
    state: &ScopeReviewState,
    source: &ScopeSourceView,
    width: usize,
) -> Vec<String> {
    let mut text = Vec::new();
    if let Some(notice) = &state.notice {
        text.extend([notice.clone(), String::new()]);
    }
    let mut detail = action_search::search_detail(state).unwrap_or_else(|| scope_detail(state));
    let position = detail.len().min(2);
    detail.splice(
        position..position,
        context::scope_context_detail(app, state),
    );
    text.extend(detail);
    if let Some(review) = &state.review {
        text.push(format!(
            "Recorded boundary approval: {}.",
            if review.record.acceptance.is_some() {
                "accepted"
            } else {
                "not accepted"
            }
        ));
    }
    text.extend(source.details());
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
