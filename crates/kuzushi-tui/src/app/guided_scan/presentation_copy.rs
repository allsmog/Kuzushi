use super::*;
use kuzushi_core::workflow_attempts::PhaseResultAction;

pub(super) fn base_question(
    flow: &GuidedScanFlow,
    header: &str,
    prompt: &str,
    detail: &str,
    options: Vec<GuidedQuestionOption>,
    multi_select: bool,
    progress: Option<String>,
) -> GuidedScanQuestionModel {
    GuidedScanQuestionModel {
        header: header.to_string(),
        prompt: prompt.to_string(),
        detail_lines: vec![detail.to_string()],
        semantic_keys: std::collections::BTreeSet::new(),
        progress,
        cursor: flow.cursor().min(options.len().saturating_sub(1)),
        options,
        multi_select,
        accept_remaining_defaults: false,
        other_open: flow.other_open(),
        other_draft: flow.other_draft().to_string(),
        other_cursor: flow.other_cursor(),
        acknowledgement: flow.acknowledgement().map(str::to_string),
        error: flow.error().map(str::to_string),
    }
}

pub(super) fn map_route_options(
    accepted: bool,
    has_prior_artifacts: bool,
) -> Vec<GuidedQuestionOption> {
    let mut options = Vec::new();
    if accepted {
        options.push(question_option(
            "Continue to Scan",
            "Reuse the accepted Map and choose discovery engines next.",
            false,
            true,
        ));
    }
    let recommended_label = if has_prior_artifacts {
        "Re-run recommended Map modules"
    } else {
        "Run recommended Map modules"
    };
    options.push(question_option(
        recommended_label,
        "Review the target-aware module set and refresh selected artifacts.",
        false,
        !accepted,
    ));
    options.push(question_option(
        "Choose Map modules",
        "Customize exactly which Map capabilities should run.",
        false,
        false,
    ));
    options.push(other_option());
    options
}

pub(super) fn context_question_options() -> Vec<GuidedQuestionOption> {
    vec![
        question_option(
            "Build context",
            "Add repository context to the Map plan before dependent modules.",
            false,
            true,
        ),
        question_option(
            "Review Map modules",
            "Return to module selection without running anything.",
            false,
            false,
        ),
        other_option(),
    ]
}

pub(super) fn module_question_option(
    row: &PlanningTaskRow,
    selected: bool,
    seed: Option<&ScanSeedContext>,
) -> GuidedQuestionOption {
    GuidedQuestionOption {
        label: row.label.to_string(),
        description: seeded_module_description(row, seed),
        selected,
        recommended: selected || seed.is_some_and(|seed| seed.recommends(row.tool_name)),
        other: false,
    }
}

/// Append the recommender's rationale to a runnable row so the checkbox reads
/// as "recommended because …". Blocked/unavailable rows keep their blocker
/// text — a reason must never drown out why a row cannot run.
fn seeded_module_description(row: &PlanningTaskRow, seed: Option<&ScanSeedContext>) -> String {
    let base = module_row_description(row);
    if row.blocker.is_some() || !row.cli_available {
        return base;
    }
    match seed.and_then(|seed| seed.reason_for(row.tool_name)) {
        Some(reason) => format!("{base} — {reason}"),
        None => base,
    }
}

pub(super) fn guided_choice_option(choice: GuidedOptionChoice) -> GuidedQuestionOption {
    GuidedQuestionOption {
        label: choice.label,
        description: choice.description,
        selected: false,
        recommended: choice.recommended,
        other: matches!(choice.value, GuidedOptionValue::Other),
    }
}

pub(super) fn result_question_option(
    phase: WorkflowPhase,
    action: PhaseResultAction,
    recommended: bool,
) -> GuidedQuestionOption {
    question_option(
        phase_result_action_label(phase, action),
        phase_result_action_description(phase, action),
        false,
        recommended,
    )
}

pub(super) fn question_option(
    label: &str,
    description: &str,
    selected: bool,
    recommended: bool,
) -> GuidedQuestionOption {
    GuidedQuestionOption {
        label: label.to_string(),
        description: description.to_string(),
        selected,
        recommended,
        other: false,
    }
}

pub(super) fn other_option() -> GuidedQuestionOption {
    GuidedQuestionOption {
        label: "Other…".to_string(),
        description: "Type a free-form answer; it is checked before changing the plan.".to_string(),
        selected: false,
        recommended: false,
        other: true,
    }
}

pub(super) fn module_row_description(row: &PlanningTaskRow) -> String {
    let state = match row.artifact_state {
        PlanningArtifactState::Cached => "cached",
        PlanningArtifactState::Invalid => "stale",
        PlanningArtifactState::Missing => "not built",
        PlanningArtifactState::Action => "will run",
    };
    if let Some(blocker) = row.blocker.as_deref() {
        return format!("blocked · {blocker}");
    }
    if !row.cli_available {
        return format!(
            "unavailable · needs {} on PATH",
            row.required_cli.unwrap_or("tool")
        );
    }
    format!("{} · {state}", row.tool_name)
}

pub(super) fn humanize_option_name(name: &str) -> String {
    let mut output = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_uppercase() && !output.is_empty() {
            output.push(' ');
        }
        output.push(if ch == '_' || ch == '-' {
            ' '
        } else {
            ch.to_ascii_lowercase()
        });
    }
    output
}

pub(super) fn phase_result_prompt(
    phase: WorkflowPhase,
    outcome: kuzushi_core::workflow_attempts::PhaseAttemptOutcome,
    routes_to_report: bool,
) -> String {
    use kuzushi_core::workflow_attempts::PhaseAttemptOutcome::*;

    match outcome {
        Completed => completed_phase_result_prompt(phase, routes_to_report),
        Partial => format!(
            "{} returned partial evidence. Review it and choose a recovery action.",
            phase.label()
        ),
        Failed => format!("{} failed. Open the run or try again.", phase.label()),
        Canceled => format!("{} was canceled. Open the run or try again.", phase.label()),
    }
}

fn completed_phase_result_prompt(phase: WorkflowPhase, routes_to_report: bool) -> String {
    match (phase, routes_to_report) {
        (WorkflowPhase::Map, _) => {
            "Map modules completed. Use these results and continue to Scan?".to_string()
        }
        (WorkflowPhase::Scan, false) => {
            "Scan modules completed. Use these candidates and continue to Review?".to_string()
        }
        (WorkflowPhase::Scan, true) => {
            "Scan completed with no reviewable findings. Use this result and open Report?"
                .to_string()
        }
        _ => format!("{} completed. What should Kuzushi do next?", phase.label()),
    }
}

fn phase_result_action_label(phase: WorkflowPhase, action: PhaseResultAction) -> &'static str {
    use PhaseResultAction::*;
    match (phase, action) {
        (WorkflowPhase::Map, SelectAndContinue) => "Use map & choose Scan modules",
        (WorkflowPhase::Scan, SelectAndContinue) => "Use scan & continue to Review",
        (WorkflowPhase::Map, Select) => "Use map",
        (WorkflowPhase::Scan, Select) => "Use scan",
        (_, SelectAndReport) => "Use & Report",
        (_, Open) => "Open run evidence",
        (_, Refine) => "Refine",
        (_, RunAgain) => "Run again",
        (_, Regenerate) => "Regenerate",
        (_, Discard) => "Discard",
        (_, SelectAndContinue) => "Use & continue",
        (_, Select) => "Use result",
    }
}

fn phase_result_action_description(
    phase: WorkflowPhase,
    action: PhaseResultAction,
) -> &'static str {
    use PhaseResultAction::*;
    match action {
        SelectAndContinue if phase == WorkflowPhase::Map => {
            "Select this Map attempt, then ask which Scan engines to run."
        }
        SelectAndContinue => "Select this attempt and follow the reality-derived next phase.",
        SelectAndReport => "Select this attempt and open the report exit.",
        Select => "Select this attempt without leaving the current phase page.",
        Open => "Inspect the canonical run receipt and trace.",
        Refine => "Draft a refinement from the exact rerun specification.",
        RunAgain => "Repeat the recorded tool and input.",
        Regenerate => "Generate a sibling attempt while retaining prior evidence.",
        Discard => "Discard this attempt selection; canonical evidence remains on disk.",
    }
}
