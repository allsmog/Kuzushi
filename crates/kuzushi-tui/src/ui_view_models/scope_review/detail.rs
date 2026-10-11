use super::*;
use crate::app::{selected_scope, ScopeReviewState};

pub(crate) fn scope_detail(state: &ScopeReviewState) -> Vec<String> {
    let Some(review) = &state.review else {
        return vec!["Build a bounded repository inventory first.".into(), "The initial draft keeps the whole repository together. You choose whether to split it. This action makes no model requests.".into(), "Optional AI suggestions are available from Actions after inventory. Scope review and scan approval remain separate.".into()];
    };
    let mut lines = if let Some(form) = state
        .form
        .as_ref()
        .filter(|form| form.kind == crate::app::ScopeEditKind::AiPriorities)
    {
        vec!["Suggest boundaries for the entire repository inventory.".into(),
            "One proposal request, at most eight primary scopes, no recursive subdivision. The next screen reviews model and shared allowance before execution.".into(),
            format!("Architecture context: {}. F3 changes this choice.", if form.omit_context { "explicitly omitted" } else { "accepted Map revision, when available" })]
    } else if state.accepting {
        acceptance_detail(state)
    } else if state.merge_target.is_some() {
        vec!["Choose the destination scope. Its boundary will include both scopes' source files, dependencies and questions. Coverage is recomputed before saving. No jobs start.".into()]
    } else if state.menu.is_some() {
        menu_detail(state)
    } else if let Some(files) = &state.files {
        let mut lines = vec![format!(
            "Files {}..{} of {}",
            files.page.offset + usize::from(!files.page.files.is_empty()),
            files.page.offset + files.page.files.len(),
            files.page.total
        )];
        lines.extend(files.page.files.clone());
        lines
    } else {
        selected_detail(state)
    };
    lines.push(String::new());
    lines.extend(source_detail(review));
    lines.extend(generation_detail(review));
    lines
}

fn generation_detail(review: &kuzushi_core::workspace::ScanScopeReview) -> Vec<String> {
    let Some(generation) = &review.record.generation else {
        return Vec::new();
    };
    let edited = serde_json::to_string(&review.record.draft)
        .map(|text| kuzushi_core::options::prompt_content_sha256(&text) != generation.draft_sha256)
        .unwrap_or(true);
    let mut lines = vec![
        format!(
            "Suggested with {}. Subsequent operator edits: {edited}.",
            crate::app::display_model_selector(&generation.model)
        ),
        format!(
            "Model input: {} bytes; {} of {} file names supplied. Run: {}.",
            generation.input_bytes,
            generation.supplied_files,
            generation.inventoried_files,
            generation.run_id
        ),
    ];
    lines.extend(generation.limitations.clone());
    lines
}

fn selected_detail(state: &ScopeReviewState) -> Vec<String> {
    let Some(review) = state.review.as_ref() else {
        return Vec::new();
    };
    if let Some(scope) = selected_scope(state) {
        let mut lines = vec![
            scope.name.clone(),
            format!("Boundary: {}", scope.paths.join(", ")),
            format!("Why: {}", scope.rationale),
            format!("Scope id: {}", scope.id),
        ];
        lines.push(format!(
            "Inventory limited: {}. Unbound included files across all scopes: {}.",
            review.coverage.inventory_limited, review.identity_omissions.total
        ));
        lines.push(format!(
            "Shared dependencies: {}",
            joined_or_none(&scope.shared_dependencies)
        ));
        lines.push(format!(
            "Open questions: {}",
            joined_or_none(&scope.open_questions)
        ));
        lines.extend(resource_detail(state));
        return lines;
    }
    coverage_detail(review)
}

fn coverage_detail(review: &kuzushi_core::workspace::ScanScopeReview) -> Vec<String> {
    let mut lines = vec![
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
            .map(|file| format!("Unbound: {file}")),
    );
    lines.push("Press f to read this category's files. Exclusions and overlap need separate acknowledgement. Uncovered or unbound included files block acceptance.".into());
    lines
}

fn joined_or_none(values: &[String]) -> String {
    if values.is_empty() {
        "none recorded".into()
    } else {
        values.join(", ")
    }
}

fn resource_detail(state: &ScopeReviewState) -> Vec<String> {
    let Some(review) = state.review.as_ref() else {
        return Vec::new();
    };
    let draft = &review.record.draft;
    vec![format!("Boundaries: {} primary scopes. Shared discovery: {}.", draft.scopes.len(), draft.shared_discovery),
        "Study context, local overrides, passes and model are reviewed in each study.".into(),
        "Scope acceptance does not approve jobs or spending. Space marks discovery boundaries; p reviews one finite study for the marked set, or the focused boundary when none are marked. Other boundaries stay unplanned.".into(),
        "Shared context adds no discovery unless explicitly selected.".into()]
}

fn acceptance_detail(state: &ScopeReviewState) -> Vec<String> {
    let Some(review) = state.review.as_ref() else {
        return Vec::new();
    };
    let c = &review.coverage;
    let mut lines = vec!["Accept boundaries only".into(), "No scans, model requests or allowance approvals occur. Any future study must bind this exact revision and receive separate approval.".into(),
        format!("Uncovered: {}. Included files without source identity: {}.", c.uncovered_files.total, review.identity_omissions.total),
        format!("Inventory limited: {}. Overlap: {}. Excluded: {}.", c.inventory_limited, c.overlaps.total, c.excluded_files.total)];
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
        _ => "Create a separate inventory draft for the current source. Earlier immutable revisions remain available. No model requests are made.",
    };
    let mut lines = vec![description.into()];
    if selected_scope(state).is_none() && state.menu.unwrap_or(0) < 6 {
        lines.push("Select a scope before using this action.".into());
    }
    lines
}

fn source_detail(review: &kuzushi_core::workspace::ScanScopeReview) -> Vec<String> {
    let source = &review.record.source;
    vec![format!("Recorded Git SHA: {}", source.git_revision.as_deref().unwrap_or("unavailable")), format!("Recorded working tree: {}", match source.dirty { Some(true) => "modified", Some(false) => "clean", None => "unavailable" }),
        format!("Source snapshot: {}", source.snapshot_hash), format!("Inventory: {}", review.record.inventory_hash),
        "Reads show recorded source. Editing and acceptance recheck current content and Git revision. A later scan missing a finding does not prove it was fixed.".into()]
}
