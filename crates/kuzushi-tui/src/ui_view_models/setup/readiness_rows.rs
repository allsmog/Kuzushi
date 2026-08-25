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
        model_row(app, selected_model_tasks),
        credential_row(app, selected_model_tasks, credential_readiness),
        prompt_row(app, selected_rows),
        budget_row(app),
    ]
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
            format!("{model} selected, but this plan does not require it"),
        ),
        (_, Some(model)) => ready_row(
            SetupRowId::Model,
            "Model",
            "EXPLICIT",
            format!("{model} · no fallback model"),
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
        return ready_row(
            SetupRowId::Credentials,
            "Credentials",
            "READY",
            readiness.label(),
        );
    }
    let detail = missing_credential_detail(app)
        .unwrap_or_else(|| "selected provider: credentials required".to_string());
    blocked_row(SetupRowId::Credentials, "Credentials", "MISSING", detail)
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

fn budget_row(app: &ShellApp) -> SetupReadinessRow {
    let Some(budget) = app.session().session_budget_usd() else {
        return optional_row(
            SetupRowId::Budget,
            "Budget",
            "NOT ENFORCED",
            "set a positive session cap, or continue without one",
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
            format!("${budget:.2} exceeds the hard ceiling ${ceiling:.2}"),
        );
    }
    ready_row(
        SetupRowId::Budget,
        "Budget",
        "ENFORCED",
        format!("${budget:.2} session cap"),
    )
}

fn ready_row(
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

fn blocked_row(
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
