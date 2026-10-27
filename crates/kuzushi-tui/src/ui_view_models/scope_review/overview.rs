//! A bounded boundary preview; the complete document remains the reader source.
use super::{context, generation, paths, scope_detail_lines, workload, ScopeSourceView};
use crate::app::{selected_scope, ScopeReviewState, ShellApp};
use crate::renderer::shared::text::{fit, wrap_document_text};
use kuzushi_core::run_lifecycle::SafeText;
use kuzushi_core::workspace::{ProposedScanScope, ScanScopeReview};

pub(crate) fn scope_display_lines(
    app: &ShellApp,
    state: &ScopeReviewState,
    source: &ScopeSourceView,
    width: usize,
) -> Vec<String> {
    let Some(mut lines) = boundary_overview(app, state) else {
        return scope_detail_lines(app, state, source, width);
    };
    if let Some(notice) = &state.notice {
        lines.splice(0..0, [notice.clone(), String::new()]);
    }
    lines
        .into_iter()
        .flat_map(|line| wrap_document_text(&line, width.max(1), width.max(1)))
        .collect()
}

fn boundary_overview(app: &ShellApp, state: &ScopeReviewState) -> Option<Vec<String>> {
    if full_document_owns_focus(state) {
        return None;
    }
    let review = state.review.as_deref()?;
    let scope = selected_scope(state)?;
    let mut lines = vec![
        scope.name.clone(),
        membership_summary(review, scope),
        path_preview(scope),
    ];
    lines.extend(workload::summary(state));
    lines.push(format!("Why: {}", preview(&scope.rationale, 120)));
    lines.extend(coverage_summary(review));
    lines.extend(
        context::scope_context_detail(app, state)
            .into_iter()
            .take(1),
    );
    lines.push(list_preview(
        "Shared dependencies",
        &scope.shared_dependencies,
    ));
    lines.push(list_preview("Open questions", &scope.open_questions));
    lines.extend(generation::generation_summary(
        review.record.generation.as_ref(),
    ));
    lines.extend(generation::correction_summary(
        review.record.correction.as_ref(),
    ));
    lines.push(
        "Next study calls and dollars: not estimated; p reviews engines and allowance.".into(),
    );
    lines.push("Tab reads the complete reason, context, source history and limits.".into());
    Some(lines)
}

fn full_document_owns_focus(state: &ScopeReviewState) -> bool {
    state.detail_reader.open
        || state.files.is_some()
        || state.merge_target.is_some()
        || editing_boundary(state)
}

fn editing_boundary(state: &ScopeReviewState) -> bool {
    state.form.is_some() || state.menu.is_some() || state.accepting
}

fn membership_summary(review: &ScanScopeReview, scope: &ProposedScanScope) -> String {
    let members = review
        .coverage
        .discovery_members
        .get(&scope.id)
        .or_else(|| review.coverage.context_members.get(&scope.id));
    members.map_or_else(
        || "Membership unavailable; inspect the recorded boundary before planning.".into(),
        |members| {
            format!(
                "Membership: {} {} · {}.",
                members.total,
                if members.total == 1 { "file" } else { "files" },
                scope_role(review, scope)
            )
        },
    )
}

fn scope_role(review: &ScanScopeReview, scope: &ProposedScanScope) -> &'static str {
    let shared = review
        .record
        .draft
        .shared_scope
        .as_ref()
        .is_some_and(|shared| shared.id == scope.id);
    if !shared {
        return "discovery";
    }
    if review.record.draft.shared_discovery {
        "shared context and discovery enabled"
    } else {
        "shared context only; no discovery jobs"
    }
}

fn path_preview(scope: &ProposedScanScope) -> String {
    let paths = scope
        .paths
        .iter()
        .take(2)
        .map(|path| paths::display_path(path))
        .collect::<Vec<_>>()
        .join(" · ");
    let remaining = scope.paths.len().saturating_sub(2);
    let extra = if remaining == 0 {
        String::new()
    } else {
        format!(" · +{remaining} paths")
    };
    format!("Boundary: {}{extra}", preview(&paths, 80))
}

fn coverage_summary(review: &ScanScopeReview) -> Vec<String> {
    let coverage = &review.coverage;
    let limits = if coverage.inventory_limited {
        "limits reported"
    } else {
        "no limit reported"
    };
    vec![
        format!(
            "Coverage: {} uncovered · {} excluded · {} overlap.",
            coverage.uncovered_files.total, coverage.excluded_files.total, coverage.overlaps.total
        ),
        format!(
            "Without content identity: {} files.",
            review.identity_omissions.total
        ),
        format!("Inventory: {} files · {limits}.", coverage.enumerated_files),
        super::detail::enumeration_summary(coverage),
    ]
}

fn list_preview(label: &str, values: &[String]) -> String {
    let Some(first) = values.first() else {
        return format!("{label}: none recorded.");
    };
    format!(
        "{label}: {} · preview: {}",
        values.len(),
        preview(first, 100)
    )
}

fn preview(value: &str, columns: usize) -> String {
    fit(SafeText::preview_line(value).as_str(), columns)
}
