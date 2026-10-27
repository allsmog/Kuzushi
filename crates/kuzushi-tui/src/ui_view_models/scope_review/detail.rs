use super::generation::generation_detail;
use super::*;
use crate::app::{selected_scope, ScopeReviewState};

pub(crate) fn scope_detail(state: &ScopeReviewState, context: Vec<String>) -> Vec<String> {
    let Some(review) = &state.review else {
        return vec!["Build a bounded repository inventory first.".into(), "The initial draft keeps the whole repository together. You choose whether to split it. This action makes no model requests.".into(), "Optional AI suggestions are available from Actions after inventory. Scope review and scan approval remain separate.".into()];
    };
    let mut lines = current_detail(state, context);
    lines.push(String::new());
    lines.extend(source_detail(review));
    lines.extend(generation_detail(review));
    lines
}

fn current_detail(state: &ScopeReviewState, context: Vec<String>) -> Vec<String> {
    if let Some(lines) = editor_detail(state) {
        return lines;
    }
    if state.menu.is_some() {
        return menu_detail(state);
    }
    if let Some(mut detail) = reading_detail(state) {
        detail.extend(context);
        return detail;
    }
    selected_detail(state, context)
}

fn reading_detail(state: &ScopeReviewState) -> Option<Vec<String>> {
    state
        .files
        .as_ref()
        .map(file_detail)
        .or_else(|| super::tree::selected_file_detail(state))
}

fn editor_detail(state: &ScopeReviewState) -> Option<Vec<String>> {
    if let Some(form) = state
        .form
        .as_ref()
        .filter(|form| form.kind == crate::app::ScopeEditKind::AiPriorities)
    {
        return Some(vec!["Suggest boundaries for the entire repository inventory.".into(),
            "One proposal request, at most eight primary scopes, no recursive subdivision. The next screen reviews model and shared allowance before execution.".into(),
            format!("Architecture context: {}. F3 changes this choice.", architecture_context(form))]);
    }
    if state.accepting {
        return Some(acceptance_detail(state));
    }
    state.merge_target.map(|_| vec!["Choose the destination scope. Its boundary will include both scopes' source files, dependencies and questions. Coverage is recomputed before saving. No jobs start.".into()])
}

fn architecture_context(form: &crate::app::ScopeEditForm) -> &'static str {
    if form.omit_context {
        "explicitly omitted"
    } else {
        "accepted Map revision, when available"
    }
}

fn file_detail(files: &crate::app::ScopeFiles) -> Vec<String> {
    let mut lines = vec![format!(
        "Files {}..{} of {}",
        files.page.offset + usize::from(!files.page.files.is_empty()),
        files.page.offset + files.page.files.len(),
        files.page.total
    )];
    lines.extend(
        files
            .page
            .files
            .iter()
            .map(|path| super::paths::display_path(path)),
    );
    lines
}

fn selected_detail(state: &ScopeReviewState, context: Vec<String>) -> Vec<String> {
    let Some(review) = state.review.as_ref() else {
        return Vec::new();
    };
    if let Some(scope) = selected_scope(state) {
        let mut lines = selected_heading(state, scope);
        lines.extend(context);
        lines.extend(super::generation::generation_summary(
            review.record.generation.as_ref(),
        ));
        lines.extend(super::generation::correction_summary(
            review.record.correction.as_ref(),
        ));
        lines.push(format!("Scope id: {}", scope.id));
        lines.push(format!(
            "Inventory limited: {}. Included files without content identity: {}.",
            review.coverage.inventory_limited, review.identity_omissions.total
        ));
        lines.push(enumeration_summary(&review.coverage));
        lines.push(format!(
            "Shared dependencies: {}",
            joined_or_none(&scope.shared_dependencies)
        ));
        lines.push(format!(
            "Open questions: {}",
            joined_or_none(&scope.open_questions)
        ));
        lines.extend(resource_detail());
        return lines;
    }
    coverage_detail(review)
}

fn selected_heading(
    state: &ScopeReviewState,
    scope: &kuzushi_core::workspace::ProposedScanScope,
) -> Vec<String> {
    let mut lines = vec![scope.name.clone()];
    lines.push(format!(
        "Boundary: {}",
        scope
            .paths
            .iter()
            .map(|path| super::paths::display_path(path))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    lines.push(format!("Why: {}", scope.rationale));
    lines.extend(super::workload::summary(state));
    lines
}

fn coverage_detail(review: &kuzushi_core::workspace::ScanScopeReview) -> Vec<String> {
    let mut lines = vec![
        enumeration_summary(&review.coverage),
        format!(
            "Inventory: {} enumerated files",
            review.coverage.enumerated_files
        ),
        format!(
            "Uncovered {} · excluded {} · overlap {}",
            review.coverage.uncovered_files.total,
            review.coverage.excluded_files.total,
            review.coverage.overlaps.total
        ),
        format!(
            "Without source content identity: {}",
            review.identity_omissions.total
        ),
    ];
    lines.extend(review.coverage.limitations.clone());
    lines.extend(
        review
            .identity_omissions
            .files
            .iter()
            .map(|file| format!("Unbound: {}", super::paths::display_path(file))),
    );
    lines.push("In the tree, f reads this category's files. Exclusions and overlap need separate acknowledgement. Uncovered or unbound included files block acceptance.".into());
    lines
}

fn enumeration_summary(coverage: &kuzushi_core::workspace::ScanScopeCoverage) -> String {
    let state = if coverage.enumeration_complete {
        "complete under inventory policy"
    } else {
        "partial or unrecorded"
    };
    format!("File enumeration: {state}. Content inspection and exclusions are separate limits.")
}

fn joined_or_none(values: &[String]) -> String {
    if values.is_empty() {
        "none recorded".into()
    } else {
        values.join(", ")
    }
}

fn resource_detail() -> Vec<String> {
    let mut lines = super::workload::guidance();
    lines.push("In the tree, Space marks discovery boundaries; p reviews the marked set, or the focused boundary when none are marked. Other boundaries stay unplanned. Scope acceptance does not approve jobs or spending.".into());
    lines
}

fn acceptance_detail(state: &ScopeReviewState) -> Vec<String> {
    let Some(review) = state.review.as_ref() else {
        return Vec::new();
    };
    let c = &review.coverage;
    let mut lines = vec!["Accept boundaries only".into(), "No scans, model requests or allowance approvals occur. Any future study must bind this exact revision and receive separate approval.".into(),
        format!("Uncovered: {}. Included files without source identity: {}.", c.uncovered_files.total, review.identity_omissions.total),
        format!("Inventory limited: {}. Overlap: {}. Excluded: {}.", c.inventory_limited, c.overlaps.total, c.excluded_files.total)];
    lines.push(enumeration_summary(c));
    lines.extend(super::workload::detail(state));
    lines.extend(c.limitations.clone());
    lines.push("Check each applicable acknowledgement. Gaps in membership or source identity cannot be waived.".into());
    lines
}

fn menu_detail(state: &ScopeReviewState) -> Vec<String> {
    let description = match state.menu.unwrap_or(0) {
        0 => "Change the selected scope's display name. Its identity and source membership stay the same.",
        1 => "Create two named child scopes using exact file or directory paths. Include every parent file, including loose files. Invalid or incomplete splits preserve your form.",
        2 => "Choose another primary scope by name. Combine membership and recompute coverage.",
        3 | 4 => "Record an explicit exclusion reason. Excluded files are disclosed and require acknowledgement before acceptance.",
        5 => "Edit the boundary rationale, shared dependency references and open questions. This does not generate scanner context.",
        6 => "Choose whether the shared scope is context only or a separate discovery boundary. It can add duplicate work and must be reviewed.",
        7 => "Replace division with a whole-repository boundary. Existing explicit exclusions stay recorded. No scan starts.",
        8 => "Review coverage limitations, duplicate discovery and exclusions before accepting the exact scope revision.",
        10 => "Plan discovery for the selected accepted boundary. The study keeps your engine choices and defaults to three passes and one worker. Other scopes remain unplanned. Draft preparation rechecks source and engine support; allowance approval and starting jobs are separate actions.",
        11 => "Remove one exact recorded exclusion rule. The form starts with its path. Other exclusions stay in force, coverage is recomputed, and the new revision needs acceptance before scanning. No work starts.",
        12 => "Request one bounded scope proposal after reviewing its model and shared allowance. No recursive subdivision or automatic follow-up requests are approved here.",
        13 => "Copy the selected primary boundary into shared context. Its original discovery membership stays unchanged. Every selected scan boundary may receive these files as context, with no additional discovery job. The new revision needs acceptance and a new study approval.",
        14 => "Remove the shared context selection while retaining primary discovery boundaries. Referencing dependencies must be edited first. Earlier accepted revisions and study plans stay unchanged. No work starts.",
        15 => "Add one named discovery boundary using exact files or directory prefixes. Complete uncovered lists of at most 32 files are prefilled; larger or partial lists require explicit paths. Coverage and overlap are recomputed. Acceptance, job planning and spending approval remain separate.",
        16 => "Read saved findings for this exact accepted boundary across recorded studies. Membership comes from authenticated requests, not file paths. Current ledger decisions stay authoritative. No discovery or model work starts. q returns to these boundaries or this action search.",
        17 => "Reload saved boundaries and current repository facts. Keep the selected boundary and earlier immutable revisions. This does not build a new inventory, start scans or make model requests.",
        _ => "Create a separate inventory draft for the current source. Earlier immutable revisions remain available. No model requests are made.",
    };
    let mut lines = state
        .selected_file()
        .map(|path| format!("Selected file: {}", super::paths::display_path(&path)))
        .into_iter()
        .collect::<Vec<_>>();
    lines.push(description.into());
    if state.menu == Some(16) {
        lines.insert(
            0,
            selected_scope(state).map_or_else(
                || "Select an accepted boundary first.".into(),
                |scope| format!("Saved findings for {}", scope.name),
            ),
        );
    }
    if boundary_action_unavailable(state) {
        lines.push("Select a scope before using this action.".into());
    }
    lines
}

fn boundary_action_unavailable(state: &ScopeReviewState) -> bool {
    match state.menu {
        Some(4) => selected_scope(state).is_none() && state.selected_file().is_none(),
        Some(0..=5) => selected_scope(state).is_none(),
        _ => false,
    }
}

fn source_detail(review: &kuzushi_core::workspace::ScanScopeReview) -> Vec<String> {
    let source = &review.record.source;
    vec![format!("Inventory membership binding: {}", if source.enumeration_hash.is_some() { "recorded; checked again before new work" } else { "legacy scope; build and accept a new inventory draft before new work" }),
        format!("Recorded Git SHA: {}", source.git_revision.as_deref().unwrap_or("unavailable")), format!("Recorded working tree: {}", match source.dirty { Some(true) => "modified", Some(false) => "clean", None => "unavailable" }),
        format!("Source snapshot: {}", source.snapshot_hash), format!("Inventory: {}", review.record.inventory_hash),
        "Reads show recorded source. Editing and acceptance recheck current content and Git revision. A later scan missing a finding does not prove it was fixed.".into()]
}
