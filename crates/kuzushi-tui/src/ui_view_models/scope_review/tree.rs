use super::*;
use crate::app::{ScopeBranch, ScopeTreeRow};
use kuzushi_core::workspace::ScanScopeReview;

pub(super) fn row_label(
    state: &ScopeReviewState,
    review: &ScanScopeReview,
    row: &ScopeTreeRow,
) -> String {
    match row {
        ScopeTreeRow::Branch(branch) => format!(
            "{} {}",
            branch_glyph(state, branch),
            branch_label(state, review, branch)
        ),
        ScopeTreeRow::File { branch, path } => file_row(state, branch, path),
        ScopeTreeRow::Page { branch, offset } => page_label(state, branch, *offset),
    }
}

fn file_row(state: &ScopeReviewState, branch: &ScopeBranch, path: &str) -> String {
    let page = state.tree_page(branch);
    let last = page.offset + page.files.len() == page.total
        && page.files.last().is_some_and(|last| last == path);
    let connector = if last { "└" } else { "├" };
    format!("  {connector} {}", paths::display_path(path))
}

fn branch_glyph(state: &ScopeReviewState, branch: &ScopeBranch) -> &'static str {
    if state.tree.expanded.contains(branch) {
        "▾"
    } else {
        "▸"
    }
}

fn branch_label(
    state: &ScopeReviewState,
    review: &ScanScopeReview,
    branch: &ScopeBranch,
) -> String {
    match branch {
        ScopeBranch::Scope(id) => scope_label(state, review, id),
        ScopeBranch::Uncovered => format!("Uncovered · {}", review.coverage.uncovered_files.total),
        ScopeBranch::Excluded => format!("Excluded · {}", review.coverage.excluded_files.total),
        ScopeBranch::Overlap => format!("Overlap · {}", review.coverage.overlaps.total),
    }
}

fn scope_label(state: &ScopeReviewState, review: &ScanScopeReview, id: &str) -> String {
    if let Some(scope) = review
        .record
        .draft
        .scopes
        .iter()
        .find(|scope| scope.id == id)
    {
        return marked_boundary_row(state, review, scope);
    }
    let Some(shared) = &review.record.draft.shared_scope else {
        return "Boundary unavailable".into();
    };
    let marker = if state.study_scope_ids.contains(id) {
        "x"
    } else {
        " "
    };
    let mode = if review.record.draft.shared_discovery {
        "discovery"
    } else {
        "context"
    };
    format!("[{marker}] Shared: {} · {mode}", shared.name)
}

fn page_label(state: &ScopeReviewState, branch: &ScopeBranch, offset: usize) -> String {
    let page = state.tree_page(branch);
    let direction = if offset < page.offset {
        "Previous"
    } else {
        "Next"
    };
    format!(
        "  {direction} files · {}..{} of {}",
        offset + 1,
        (offset + crate::app::SCOPE_TREE_PAGE_SIZE).min(page.total),
        page.total
    )
}

pub(super) fn selected_file_detail(state: &ScopeReviewState) -> Option<Vec<String>> {
    match state.selected_row()? {
        ScopeTreeRow::File { branch, path } => Some(vec![
            format!("File: {}", paths::display_path(&path)),
            format!("Membership: {}", branch_label(state, state.review.as_ref()?, &branch)),
            file_action_hint(&branch).into(),
            "In the tree, Space marks only boundary rows. Left returns to the parent. f reads this branch's full file list.".into(),
        ]),
        ScopeTreeRow::Page { branch, offset } => Some(vec![page_label(state, &branch, offset),
            "In the tree, Enter loads one recorded membership page. No model requests or scan jobs start.".into()]),
        _ => None,
    }
}

fn file_action_hint(branch: &ScopeBranch) -> &'static str {
    if branch == &ScopeBranch::Excluded {
        return "In the tree, Enter reviews the exclusion rule covering this file. Restoring a directory rule can include other files; save recomputes coverage and clears acceptance.";
    }
    "In the tree, Enter opens file actions. Exclude pre-fills this exact path; save recomputes coverage and clears acceptance."
}
