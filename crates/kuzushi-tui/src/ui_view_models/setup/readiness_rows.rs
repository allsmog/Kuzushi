use super::*;

pub(super) fn readiness_rows(
    app: &ShellApp,
    selected_rows: &[&crate::app::PlanningTaskRow],
    selected_model_tasks: usize,
    credential_readiness: CredentialReadiness,
) -> Vec<SetupReadinessRow> {
    vec![
        target_row(app),
        plan_row(app, selected_rows, selected_model_tasks),
        threat_model_row(app, selected_rows),
        model_row(app, selected_model_tasks),
        credential_row(app, selected_model_tasks, credential_readiness),
        prompt_row(app, selected_rows),
        budget_row(app, selected_model_tasks),
    ]
}

fn threat_model_row(
    app: &ShellApp,
    selected_rows: &[&crate::app::PlanningTaskRow],
) -> SetupReadinessRow {
    if app.context_import_selected() {
        return super::context_import::import_row(app);
    }
    generated_context_row(app, selected_rows)
}

fn generated_context_row(
    app: &ShellApp,
    selected_rows: &[&crate::app::PlanningTaskRow],
) -> SetupReadinessRow {
    let selected = selected_rows
        .iter()
        .any(|row| row.id == crate::app::PlanningTaskId::BuildThreatModel);
    if !selected {
        return optional_row(
            SetupRowId::ThreatModel,
            "Threat model",
            "NOT SELECTED",
            "add Build threat model to the Map plan to configure it",
        );
    }
    let summary = app.map_run_config_summary();
    if let Some(error) = summary.scope_error {
        return blocked_row(SetupRowId::ThreatModel, "Threat model", "SCOPE", error);
    }
    if summary.review_required {
        return threat_model_review_row(summary.selected_scopes);
    }
    ready_row(
        SetupRowId::ThreatModel,
        "Threat model",
        "READY",
        threat_model_ready_detail(&summary),
    )
}

fn threat_model_review_row(selected_scopes: usize) -> SetupReadinessRow {
    blocked_row(
        SetupRowId::ThreatModel,
        "Threat model",
        "REVIEW",
        format!(
            "{selected_scopes} scopes selected · Enter and confirm above the {}-scope review threshold",
            crate::app::ALL_SCOPES_REVIEW_THRESHOLD
        ),
    )
}

fn threat_model_ready_detail(summary: &crate::app::MapRunConfigSummary) -> String {
    format!(
        "{} · {} · {} build(s) · {} · {} design doc(s) · {} context row(s)",
        summary.methodology,
        summary.scope,
        summary.selected_scopes,
        summary.cost,
        summary.design_docs,
        summary.context_rows
    )
}

fn target_row(app: &ShellApp) -> SetupReadinessRow {
    match app.target() {
        Some(target) => ready_row(
            SetupRowId::Target,
            "Target",
            "CONFIRMED",
            target.display().to_string(),
        ),
        None => blocked_row(
            SetupRowId::Target,
            "Target",
            "MISSING",
            "choose a target explicitly; cwd is never assumed",
        ),
    }
}

fn plan_row(
    app: &ShellApp,
    selected_rows: &[&crate::app::PlanningTaskRow],
    selected_model_tasks: usize,
) -> SetupReadinessRow {
    if let Some(row) = plan_blocker(app, selected_rows) {
        return row;
    }
    let deterministic = selected_rows.len().saturating_sub(selected_model_tasks);
    ready_row(
        SetupRowId::Plan,
        "Map plan",
        "READY",
        format!(
            "{} selected · {deterministic} deterministic · {selected_model_tasks} model-backed",
            selected_rows.len()
        ),
    )
}

fn plan_blocker(
    app: &ShellApp,
    selected_rows: &[&crate::app::PlanningTaskRow],
) -> Option<SetupReadinessRow> {
    if app.engagement.planning_picker().profile_pending() {
        return Some(optional_row(
            SetupRowId::Plan,
            "Map plan",
            "PROFILING",
            "conservative choices are ready; target-aware recommendations will refresh",
        ));
    }
    if selected_rows.is_empty() {
        return Some(empty_plan_row(app));
    }
    missing_prerequisite_row(selected_rows).or_else(|| invalid_option_row(app, selected_rows))
}

/// Nothing is checked. On a target with Map work left to plan that is a real
/// blocker, but on a target whose recommended Map artifacts already exist it is
/// the honest resting state — the plan editor already shows every row as
/// `SKIP · cached`, so Setup must not claim the run is unconfigured.
fn empty_plan_row(app: &ShellApp) -> SetupReadinessRow {
    match current_map_artifacts(app) {
        Some(cached) => optional_row(
            SetupRowId::Plan,
            "Map plan",
            "NOTHING TO RUN",
            format!(
                "{cached} cached Map artifact(s) will be reused · Enter to choose reuse, run, or skip"
            ),
        ),
        None => blocked_row(
            SetupRowId::Plan,
            "Map plan",
            "EMPTY",
            "select at least one Map task",
        ),
    }
}

/// How many Map artifacts are already on disk, when no recommended row still
/// has work left. `None` while a recommended row is uncached: an operator who
/// unchecked real work has an empty plan, not a reusable one.
///
/// Reality, not the recommendation set, decides. A prior failed or interrupted
/// attempt keeps its task recommended even after a later run left the artifact
/// on disk; the picker reconciles that by reusing the cached artifact and
/// leaving the row unchecked, so Setup must read the same reality instead of
/// calling the resulting empty plan unconfigured.
fn current_map_artifacts(app: &ShellApp) -> Option<usize> {
    let picker = app.engagement.planning_picker();
    if picker
        .tasks()
        .iter()
        .any(|row| picker.default_selected().contains(&row.id) && !is_cached_planning_row(row))
    {
        return None;
    }
    let cached = picker
        .tasks()
        .iter()
        .filter(|row| is_cached_planning_row(row))
        .count();
    (cached > 0).then_some(cached)
}

fn is_cached_planning_row(row: &crate::app::PlanningTaskRow) -> bool {
    row.artifact_state == crate::app::PlanningArtifactState::Cached
}

fn missing_prerequisite_row(
    selected_rows: &[&crate::app::PlanningTaskRow],
) -> Option<SetupReadinessRow> {
    let blocked = selected_rows
        .iter()
        .filter(|row| !row.cli_available)
        .map(|row| row.label)
        .collect::<Vec<_>>();
    (!blocked.is_empty()).then(|| {
        blocked_row(
            SetupRowId::Plan,
            "Map plan",
            "BLOCKED",
            format!("missing prerequisite for {}", blocked.join(", ")),
        )
    })
}

fn invalid_option_row(
    app: &ShellApp,
    selected_rows: &[&crate::app::PlanningTaskRow],
) -> Option<SetupReadinessRow> {
    let tasks = selected_rows.iter().map(|row| row.id).collect::<Vec<_>>();
    if let Err(error) = app.validate_context_import_plan(&tasks) {
        return Some(blocked_row(
            SetupRowId::Plan,
            "Map plan",
            "OPTIONS",
            error.to_string(),
        ));
    }
    selected_rows.iter().find_map(|row| {
        app.resolved_input_for_planning_task(row.id)
            .err()
            .map(|error| {
                blocked_row(
                    SetupRowId::Plan,
                    "Map plan",
                    "OPTIONS",
                    format!("{}: {error}", row.label),
                )
            })
    })
}

fn model_row(app: &ShellApp, selected_model_tasks: usize) -> SetupReadinessRow {
    if let Some(error) = incompatible_model_error(app, selected_model_tasks) {
        return blocked_row(SetupRowId::Model, "Model", "INCOMPATIBLE", error);
    }
    match (selected_model_tasks, app.config().model.as_deref()) {
        (0, None) => optional_row(
            SetupRowId::Model,
            "Model",
            "NOT NEEDED",
            "the selected Map plan is deterministic/runtime-free",
        ),
        (0, Some(model)) => optional_row(
            SetupRowId::Model,
            "Model",
            "OPTIONAL",
            format!(
                "{} selected, but this plan does not require it",
                crate::app::display_model_selector(model)
            ),
        ),
        (_, Some(model)) => ready_row(
            SetupRowId::Model,
            "Model",
            &crate::app::display_model_selector(model),
            format!(
                "{} · no fallback model",
                crate::app::display_model_selector(model)
            ),
        ),
        (_, None) => blocked_row(
            SetupRowId::Model,
            "Model",
            "MISSING",
            format!("{selected_model_tasks} selected task(s) require an explicit model"),
        ),
    }
}

fn incompatible_model_error(app: &ShellApp, selected_model_tasks: usize) -> Option<String> {
    if selected_model_tasks == 0 {
        return None;
    }
    let model = app.config().model.as_deref()?;
    if let Err(error) = kuzushi_core::runtime::validate_model_spec(model) {
        return Some(error.to_string());
    }
    let provider = model.split_once(':').map(|(provider, _)| provider)?;
    (!matches!(provider, "anthropic" | "openai" | "openai-codex")).then(|| {
        format!(
            "provider {provider:?} is unavailable to the configured agent runtime; select a compatible model"
        )
    })
}

fn credential_row(
    app: &ShellApp,
    selected_model_tasks: usize,
    readiness: CredentialReadiness,
) -> SetupReadinessRow {
    if selected_model_tasks == 0 {
        return optional_row(
            SetupRowId::Credentials,
            "Credentials",
            "NOT NEEDED",
            readiness.label(),
        );
    }
    if readiness.is_ready() {
        return present_credential_row(readiness);
    }
    if readiness == CredentialReadiness::OAuthRepair {
        return blocked_row(
            SetupRowId::Credentials,
            "Credentials",
            "REPAIR",
            readiness.detail(),
        );
    }
    let detail = missing_credential_detail(app)
        .unwrap_or_else(|| "selected provider: credentials required".to_string());
    blocked_row(SetupRowId::Credentials, "Credentials", "MISSING", detail)
}

fn present_credential_row(readiness: CredentialReadiness) -> SetupReadinessRow {
    let mut row = ready_row(
        SetupRowId::Credentials,
        "Credentials",
        readiness.label(),
        readiness.detail(),
    );
    if readiness == CredentialReadiness::OAuthRefreshable {
        row.tone = SetupReadinessTone::Attention;
    }
    row
}

fn missing_credential_detail(app: &ShellApp) -> Option<String> {
    let model = app.config().model.as_deref()?;
    let provider = model.split_once(':')?.0;
    crate::app::AuthProvider::from_scene_provider(provider)
        .map(|auth| auth.missing_credential_guidance(model, provider))
}

fn prompt_row(app: &ShellApp, selected_rows: &[&crate::app::PlanningTaskRow]) -> SetupReadinessRow {
    let prompt_tasks = selected_rows
        .iter()
        .filter(|row| !app.prompt_specs_for_tool(row.tool_name).is_empty())
        .count();
    if prompt_tasks == 0 {
        return optional_row(
            SetupRowId::Prompt,
            "Prompt",
            "NOT NEEDED",
            "no selected task exposes a prompt override",
        );
    }
    ready_row(
        SetupRowId::Prompt,
        "Prompt",
        "DEFAULTS READY",
        format!("{prompt_tasks} task(s) use built-in or target-owned prompt text"),
    )
}

fn budget_row(app: &ShellApp, model_tasks: usize) -> SetupReadinessRow {
    if model_tasks > 0 {
        return optional_row(SetupRowId::Budget, "Allowance", "APPROVAL NEXT",
            "Start Map opens a fixed plan. Set total calls and protected review, then approve before any jobs start. Dollar costs may be unavailable.");
    }
    observed_budget_row(app)
}

fn observed_budget_row(app: &ShellApp) -> SetupReadinessRow {
    let Some(budget) = app.session().session_budget_usd() else {
        return optional_row(
            SetupRowId::Budget,
            "Budget",
            "NOT ENFORCED",
            "set an observed spending stop, or continue without one",
        );
    };
    if !budget.is_finite() || budget <= 0.0 {
        return blocked_row(
            SetupRowId::Budget,
            "Budget",
            "INVALID",
            "budget must be a finite positive USD amount",
        );
    }
    if app
        .config()
        .operator
        .spend_hard_ceiling_usd
        .is_some_and(|ceiling| budget > ceiling)
    {
        let ceiling = app.config().operator.spend_hard_ceiling_usd.unwrap_or(0.0);
        return blocked_row(
            SetupRowId::Budget,
            "Budget",
            "OVER CEILING",
            format!("${budget:?} exceeds the hard ceiling ${ceiling:?}"),
        );
    }
    ready_row(
        SetupRowId::Budget,
        "Budget",
        "OBSERVED STOP",
        format!("${budget:?} after cost receipts; charges may exceed this amount"),
    )
}

pub(super) fn ready_row(
    id: SetupRowId,
    label: &'static str,
    status: &str,
    detail: impl Into<String>,
) -> SetupReadinessRow {
    row(id, label, status, detail, SetupReadinessTone::Ready, false)
}

fn optional_row(
    id: SetupRowId,
    label: &'static str,
    status: &str,
    detail: impl Into<String>,
) -> SetupReadinessRow {
    row(
        id,
        label,
        status,
        detail,
        SetupReadinessTone::Optional,
        false,
    )
}

pub(super) fn blocked_row(
    id: SetupRowId,
    label: &'static str,
    status: &str,
    detail: impl Into<String>,
) -> SetupReadinessRow {
    row(id, label, status, detail, SetupReadinessTone::Blocked, true)
}

fn row(
    id: SetupRowId,
    label: &'static str,
    status: &str,
    detail: impl Into<String>,
    tone: SetupReadinessTone,
    blocks: bool,
) -> SetupReadinessRow {
    let detail = detail.into();
    SetupReadinessRow {
        id,
        label,
        status: status.to_string(),
        blocker: blocks.then(|| detail.clone()),
        detail,
        tone,
    }
}
