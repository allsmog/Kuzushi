//! Presentation of a finite study. Values come from the form or frozen receipt.
use crate::app::{BatchScanConfig, BatchScanConfigRow};
use crate::renderer::shared::text::wrap_text;
use ratatui::layout::Rect;

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
        area.y + 2,
        area.width.saturating_sub(4),
        area.height.saturating_sub(5),
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

pub(crate) fn study_row_value(config: &BatchScanConfig, row: BatchScanConfigRow) -> String {
    match row {
        BatchScanConfigRow::Trials => config.trials.to_string(),
        BatchScanConfigRow::Workers => format!("{}", config.effective_workers),
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
    config
        .projected_cost_usd()
        .map_or_else(|| "unknown".into(), |cost| format!("~${cost:.4}"))
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
        _ => allowance_description(config),
    }
}

fn allowance_description(config: &BatchScanConfig) -> Vec<String> {
    match config.selected_row() {
        BatchScanConfigRow::ProviderCalls => vec!["Total provider requests across this investigation, including internal turns and transport retries. Dollar charges are uncertain; this is not a dollar ceiling.".into()],
        BatchScanConfigRow::ReviewCalls => vec!["Calls reserved within the total for Review and Report. Discovery cannot use them. Choose zero explicitly to reserve none.".into()],
        BatchScanConfigRow::Attempts => vec!["Maximum starts per fixed job. Failed and canceled starts consume attempts. Each provider retry also consumes a provider call. No additional passes or recursive jobs are created.".into()],
        _ => action_description(config),
    }
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
    match config.projected_cost_usd().zip(config.prior_run_id.as_deref()) {
        Some((cost, id)) => vec![format!("Historical projection ${cost:.4} from {id}. Not a guarantee: prompt size, turns and retries may differ. Enter cycles completed scans with exact cost receipts.")],
        None => vec!["Cost not estimated. No exact prior scan selected. Enter cycles available completed scans with exact cost receipts; unknown cost is never zero.".into()],
    }
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
        format!("Approved model: {}", allowance.model),
        "Revising work preserves all consumption. Dollar ceiling not enforced.".into(),
    ]
}
