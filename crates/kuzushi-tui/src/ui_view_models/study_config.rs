//! Presentation of a finite study. Values come from the form or frozen receipt.
use crate::app::{BatchScanConfig, BatchScanConfigRow};
use crate::renderer::shared::text::wrap_text;
use ratatui::layout::Rect;
mod controls;
mod resources;
pub(crate) use controls::study_controls_hint;
pub(crate) use resources::study_resource_lines;

pub(crate) fn study_config_area(columns: u16, rows: u16) -> Rect {
    let width = columns.min(120);
    Rect::new((columns - width) / 2, 0, width, rows)
}

pub(crate) fn study_projection(app: &crate::ShellApp) -> Option<BatchScanConfig> {
    let mut config = app.router.campaign().batch_scan_config.clone()?;
    if let Some(notice) =
        crate::ui_view_models::notice_banner_model(app).filter(|notice| notice.dismiss_on_escape)
    {
        config.notice = Some(format!(
            "ATTENTION: {}\nEsc dismisses this message and returns to your draft.",
            notice.message
        ));
    }
    Some(config)
}

pub(crate) struct StudyConfigLayout {
    pub list: Rect,
    pub detail: Rect,
    pub controls: Rect,
}

pub(crate) fn study_config_layout(area: Rect) -> StudyConfigLayout {
    let body = Rect::new(
        area.x + 2,
        area.y + 3,
        area.width.saturating_sub(4),
        area.height.saturating_sub(6),
    );
    let controls = Rect::new(body.x, area.bottom().saturating_sub(3), body.width, 2);
    if area.width >= 100 && area.height >= 20 {
        return StudyConfigLayout {
            list: Rect::new(body.x, body.y, 42, body.height),
            detail: Rect::new(
                body.x + 44,
                body.y,
                body.width.saturating_sub(44),
                body.height,
            ),
            controls,
        };
    }
    let list_rows = (body.height / 2).clamp(1, 8).min(body.height);
    StudyConfigLayout {
        list: Rect::new(body.x, body.y, body.width, list_rows),
        detail: Rect::new(
            body.x,
            body.y + list_rows + 1,
            body.width,
            body.height.saturating_sub(list_rows + 1),
        ),
        controls,
    }
}

pub(crate) fn study_allowance_summary(config: &BatchScanConfig, width: usize) -> String {
    if config.study.accounting_error.is_some() {
        return "Accounting unavailable · work blocked".into();
    }
    let Some(allowance) = &config.study.allowance else {
        return "Allowance not approved".into();
    };
    if width >= 72 {
        return format!(
            "Calls: {} committed / {} total · {} unresolved · {} Review left",
            allowance.committed_calls,
            allowance.limits.max_provider_calls,
            allowance.unresolved_calls,
            allowance.protected_review_remaining()
        );
    }
    compact_allowance_summary(allowance, width)
}

fn compact_allowance_summary(
    allowance: &kuzushi_core::allowance::AllowanceSnapshot,
    width: usize,
) -> String {
    let calls = format!(
        "Calls {}/{}",
        allowance.committed_calls, allowance.limits.max_provider_calls
    );
    let summary = format!(
        "{calls} · Review {}",
        allowance.protected_review_remaining()
    );
    if summary.len() <= width {
        summary
    } else {
        calls
    }
}

#[cfg(test)]
mod tests;

pub(crate) fn study_row_value(config: &BatchScanConfig, row: BatchScanConfigRow) -> String {
    match row {
        BatchScanConfigRow::Trials => config.trials.to_string(),
        BatchScanConfigRow::Workers => format!("{}", config.effective_workers),
        BatchScanConfigRow::Engines => engine_summary(config),
        BatchScanConfigRow::Context => if config.study.receipt.is_some() {
            "frozen"
        } else {
            "not frozen"
        }
        .into(),
        _ => allowance_row_value(config, row),
    }
}

fn allowance_row_value(config: &BatchScanConfig, row: BatchScanConfigRow) -> String {
    match row {
        BatchScanConfigRow::ProviderCalls => optional_limit(config.study.max_provider_calls),
        BatchScanConfigRow::ReviewCalls => optional_limit(config.study.protected_review_calls),
        BatchScanConfigRow::Attempts => config.study.max_job_attempts.to_string(),
        _ => other_row_value(config, row),
    }
}

fn other_row_value(config: &BatchScanConfig, row: BatchScanConfigRow) -> String {
    if row == BatchScanConfigRow::Launch {
        return config.study.next_action().into();
    }
    resources::row_value(config)
}

fn optional_limit(value: Option<usize>) -> String {
    value.map_or_else(|| "set explicitly".into(), |value| value.to_string())
}

pub(crate) fn study_detail_lines(config: &BatchScanConfig, width: usize) -> Vec<String> {
    let mut text = Vec::new();
    if let Some(notice) = &config.notice {
        text.extend([notice.clone(), String::new()]);
    }
    text.extend(row_description(config));
    text.into_iter()
        .flat_map(|line| wrap_text(&line, width.max(1)))
        .collect()
}

fn row_description(config: &BatchScanConfig) -> Vec<String> {
    match config.selected_row() {
        BatchScanConfigRow::Trials => vec![format!("{} fresh discovery passes with identical source, context and scan options. Repetition does not prove correctness. Editing prepares a new immutable plan.", config.trials)],
        BatchScanConfigRow::Workers => vec![format!("Requested {} workers; {} permitted. {}", config.requested_workers, config.effective_workers, config.worker_clamp_reason.as_deref().unwrap_or("One worker is the default. More workers can consume the shared allowance faster."))],
        BatchScanConfigRow::Context => context_description(config),
        BatchScanConfigRow::Engines => vec!["Enter chooses discovery engines for this study. Unsupported scope contracts are explained before selection. Choices change only the draft; source, dependencies, credentials and allowance are checked before execution.".into(), format!("Current: {}", engine_summary(config))],
        _ => allowance_description(config),
    }
}

fn engine_summary(config: &BatchScanConfig) -> String {
    let Some(input) = config.study.scan_input.as_ref() else {
        return "current settings".into();
    };
    if input["taskMode"].as_str() != Some("manual") {
        return "automatic".into();
    }
    let engines = input["tasks"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>();
    if engines.is_empty() {
        return "none selected".into();
    }
    engines.join(", ")
}

fn allowance_description(config: &BatchScanConfig) -> Vec<String> {
    let description = match config.selected_row() {
        BatchScanConfigRow::ProviderCalls => "Total provider requests across this investigation, including internal turns and transport retries. Dollar charges are uncertain; this is not a dollar ceiling.",
        BatchScanConfigRow::ReviewCalls => "Calls reserved within the total for Review and Report. Discovery cannot use them. Choose zero explicitly to reserve none.",
        BatchScanConfigRow::Attempts => "Maximum starts per fixed job. Failed and canceled starts consume attempts. Each provider retry also consumes a provider call. No additional passes or recursive jobs are created.",
        _ => return action_description(config),
    };
    let mut text = vec![description.into()];
    text.extend(allowance_status_lines(config));
    text
}

fn action_description(config: &BatchScanConfig) -> Vec<String> {
    if config.selected_row() == BatchScanConfigRow::PriorRun {
        return cost_description(config);
    }
    let mut text = vec![config.study.next_action().into(), "Prepare → review allowance → open jobs → start. Each action requires your input. Approval starts no jobs.".into()];
    text.extend(allowance_status_lines(config));
    text
}

fn cost_description(config: &BatchScanConfig) -> Vec<String> {
    let mut lines = study_resource_lines(config);
    lines.push("Enter cycles completed SAST scans or clears the selection. Preparation checks whether their recorded conditions match this draft.".into());
    lines
}

fn context_description(config: &BatchScanConfig) -> Vec<String> {
    let Some(receipt) = &config.study.receipt else {
        return vec![format!("Target: {}", config.target.display()), "Enter chooses an immutable context revision or explicitly omits context. Prepare the draft to freeze the selected scan options, source snapshot and exact context revision. Planning makes no model requests.".into()];
    };
    let source = &receipt.equivalence.components;
    let git = source.target_git.as_ref().map_or_else(
        || "Git SHA unavailable".into(),
        |git| format!("Git SHA: {} · dirty: {}", git.sha, git.dirty),
    );
    vec![
        format!("Target: {}", config.target.display()),
        format!("Study: {}", receipt.campaign_id), git,
        format!("Source content: {}", source.workspace_identity),
        format!("Model: {}", source.model.as_deref().unwrap_or("runtime-free selection")),
        format!("Context: {}", receipt.scan_input.get("threatModelRef").filter(|value| !value.is_null()).map_or_else(|| "explicitly omitted".into(), ToString::to_string)),
        format!("Exact scan options: {}", receipt.scan_input),
        format!("Scope digest: {}", source.scope_sha256),
        format!("Plan digest: {}", receipt.plan_sha256),
        "These are recorded identities. Approval and execution refuse source or configuration drift. A later pass missing a finding does not mean it was fixed.".into(),
    ]
}

pub(crate) fn allowance_status_lines(config: &BatchScanConfig) -> Vec<String> {
    let study = &config.study;
    if let Some(error) = &study.accounting_error {
        return vec![
            format!("Accounting unavailable: {error}"),
            "No work can start. Restore the recorded evidence and reopen this form.".into(),
        ];
    }
    let Some(allowance) = &study.allowance else {
        return vec![
            format!("Investigation: {}", study.investigation_id),
            "Allowance not approved.".into(),
        ];
    };
    vec![
        format!(
            "Investigation: {} · revision {}",
            allowance.investigation_id, allowance.revision
        ),
        format!(
            "Calls: {} committed / {} total · {} unresolved",
            allowance.committed_calls,
            allowance.limits.max_provider_calls,
            allowance.unresolved_calls
        ),
        format!(
            "Available: {} context/scan · {} protected review",
            allowance.remaining_discovery_calls(),
            allowance.protected_review_remaining()
        ),
        format!(
            "Approved model: {}",
            crate::app::display_model_selector(&allowance.model)
        ),
        "Revising work preserves all consumption. Dollar ceiling not enforced.".into(),
    ]
}
