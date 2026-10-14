//! Presentation of a finite study. Values come from the form or frozen receipt.
use crate::app::{BatchScanConfig, BatchScanConfigRow};
use crate::renderer::shared::text::wrap_text;
use ratatui::layout::Rect;
pub(crate) mod brief;
mod context_results;
mod controls;
mod engine_inputs;
mod prepared_settings;
mod resources;
mod source_details;
pub(crate) use context_results::{context_result_jobs, context_result_lines};
pub(crate) use controls::{study_controls_hint, study_read_hint};
pub(crate) use resources::study_resource_lines;
pub(crate) use source_details::{context_reference_summary, supporting_context_summary};

pub(crate) fn study_config_area(columns: u16, rows: u16) -> Rect {
    let width = columns.min(120);
    Rect::new((columns - width) / 2, 0, width, rows)
}

pub(crate) fn study_projection(app: &crate::ShellApp) -> Option<BatchScanConfig> {
    let mut config = app.router.campaign().batch_scan_config.clone()?;
    config.source_option_specs = app
        .registry()
        .resolve_tool("sast:scan")
        .map_or_else(Vec::new, |tool| tool.options.clone());
    let message = crate::ui_view_models::notice_banner_model(app)
        .filter(|notice| notice.dismiss_on_escape)
        .map(|notice| notice.message)
        .or_else(|| config.study.preparation_error.clone());
    if let Some(message) = message {
        config.notice = Some(format!(
            "ATTENTION: {}\nEsc dismisses this message and returns to your draft.",
            message
        ));
    }
    Some(config)
}

pub(crate) fn study_surface_title(config: &BatchScanConfig) -> &'static str {
    if config.detail_reader_scroll.is_some() {
        return config.study.preparation_error.as_ref().map_or_else(
            || source_details::reader_title(config),
            |_| "PREPARATION DETAILS",
        );
    }
    if config.study.approved() {
        "APPROVED STUDY"
    } else {
        "PLAN A STUDY"
    }
}

pub(crate) struct StudyConfigLayout {
    pub list: Rect,
    pub detail: Rect,
    pub controls: Rect,
}

pub(crate) fn study_reader_layout(area: Rect, expanded: bool) -> StudyConfigLayout {
    let mut layout = study_config_layout(area);
    if expanded {
        layout.list.height = 0;
        layout.detail = Rect::new(
            area.x + 2,
            area.y + 3,
            area.width.saturating_sub(4),
            area.height.saturating_sub(6),
        );
    }
    layout
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
        return failed_allowance_summary(config, width);
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

fn failed_allowance_summary(config: &BatchScanConfig, width: usize) -> String {
    let Some(allowance) = &config.study.allowance else {
        return "Accounting unavailable · work blocked".into();
    };
    if width < 72 {
        return format!(
            "Last read {}/{} · blocked",
            allowance.committed_calls, allowance.limits.max_provider_calls
        );
    }
    format!(
        "Last read: {} committed / {} total · {} unresolved · {} Review left · blocked",
        allowance.committed_calls,
        allowance.limits.max_provider_calls,
        allowance.unresolved_calls,
        allowance.protected_review_remaining()
    )
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
        BatchScanConfigRow::Brief => config
            .study
            .brief
            .as_ref()
            .map_or("not selected".into(), |brief| {
                format!("revision {}", brief.reference.revision)
            }),
        BatchScanConfigRow::Context => if config.study.plan_identity().is_some() {
            "frozen"
        } else {
            "not frozen"
        }
        .into(),
        BatchScanConfigRow::ContextComparison => {
            if config.study.context_baseline_run_id.is_some() {
                "baseline selected"
            } else {
                "off"
            }
            .into()
        }
        BatchScanConfigRow::ContextCases => format!(
            "{} cases · {} jobs",
            config.study.matrix.cases.len(),
            config.study.matrix.planned_jobs()
        ),
        BatchScanConfigRow::CasePasses => config
            .study
            .matrix
            .cases
            .get(config.study.matrix.cursor)
            .map(|case| case.passes.to_string())
            .unwrap_or_else(|| "Select a case".into()),
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
    if config.study.preparation_error.is_none() {
        text.extend(row_description(config));
    }
    text.into_iter()
        .flat_map(|line| wrap_text(&line, width.max(1)))
        .collect()
}

fn row_description(config: &BatchScanConfig) -> Vec<String> {
    match config.selected_row() {
        BatchScanConfigRow::Trials => discovery_pass_lines(config),
        BatchScanConfigRow::Workers => vec![format!("Requested {} workers; {} permitted. {}", config.requested_workers, config.effective_workers, config.worker_clamp_reason.as_deref().unwrap_or("One worker is the default. More workers can consume the shared allowance faster."))],
        BatchScanConfigRow::Context => context_description(config),
        BatchScanConfigRow::Brief => brief::selected_lines(config),
        BatchScanConfigRow::Engines => vec!["Enter chooses discovery engines for this study. Unsupported scope contracts are explained before selection. Choices change only the draft; source, dependencies, credentials and allowance are checked before execution.".into(), format!("Current: {}", engine_summary(config))],
        BatchScanConfigRow::ContextComparison => context_experiment_lines(config),
        BatchScanConfigRow::ContextCases => vec!["Enter edits a finite set of context cases. Choose an explicit baseline; each case has its own exact revision and repetitions. Other scan conditions stay fixed. All jobs share one allowance and need approval; missing observations cannot establish a fix.".into()],
        _ => allowance_description(config),
    }
}

fn discovery_pass_lines(config: &BatchScanConfig) -> Vec<String> {
    if !config.study.matrix.cases.is_empty() {
        return vec![format!("{} passes is the default for newly added context cases. Existing cases keep their own repetitions; p in Context cases edits the selected case. Approval covers the sum of all case jobs.", config.trials)];
    }
    vec![format!("{} fresh discovery passes with identical source, context and scan options. Repetition does not prove correctness. Editing prepares a new immutable plan.", config.trials)]
}

fn context_experiment_lines(config: &BatchScanConfig) -> Vec<String> {
    let Some(run) = &config.study.context_baseline_run_id else {
        return vec!["Identical-condition repetitions. Select a completed run in Usage evidence, then Enter here enables a context comparison.".into()];
    };
    let mut lines = vec![format!("Compare candidate context with baseline run: {run}"),
        format!("{} fixed candidate passes. The baseline is historical work and is never rerun automatically.",config.trials),
        "Only context may differ. Source, scope, scanner options, model, runtime and prompts must match. Changed context does not establish which finding is true.".into(),
        "Costs may change with context. Historical usage remains visible; it is not a calibrated estimate for the candidate.".into(),
        "Enter reviews the candidate passes once a plan is frozen. x there clears comparison; spending and completed work remain recorded.".into()];
    if config.study.context_experiment.is_some() {
        lines.push(
            "Baseline conditions authenticated for this frozen plan. Approval checks them again."
                .into(),
        );
    }
    lines
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
    lines.push(if config.study.scope_draft.is_some() || !config.study.matrix.cases.is_empty() {
        "Enter chooses or clears one prior study. Preparing a new draft authenticates its complete passes against each selected case."
    } else {
        "Enter cycles completed SAST scans or clears the selection. Preparation checks whether their recorded conditions match this draft."
    }.into());
    lines
}

fn context_description(config: &BatchScanConfig) -> Vec<String> {
    source_details::source_lines(config)
}

fn context_description_body(config: &BatchScanConfig) -> Vec<String> {
    if let Some(lines) = scope_study_description(config) {
        return lines;
    }
    if let Some(receipt) = &config.study.matrix.receipt {
        return crate::ui_view_models::context_matrix_conditions(receipt);
    }
    let Some(receipt) = &config.study.receipt else {
        return vec![format!("Target: {}", config.target.display()), "Enter chooses an immutable context revision or explicitly omits context. Prepare the draft to freeze the selected scan options, source snapshot and exact context revision. Planning makes no model requests.".into()];
    };
    let source = &receipt.equivalence.components;
    let git = source.target_git.as_ref().map_or_else(
        || "Git SHA unavailable".into(),
        |git| format!("Git SHA: {} · dirty: {}", git.sha, git.dirty),
    );
    let mut lines = vec![
        format!("Target: {}", config.target.display()),
        format!("Study: {}", receipt.campaign_id),
        git,
        format!("Source content: {}", source.workspace_identity),
        format!(
            "Model: {}",
            source.model.as_deref().unwrap_or("runtime-free selection")
        ),
        format!(
            "Context: {}",
            context_reference_summary(&receipt.scan_input)
        ),
        format!("Scope digest: {}", source.scope_sha256),
        format!("Plan digest: {}", receipt.plan_sha256),
    ];
    if let Some(summary) = agentic_preparation_summary(&receipt.scan_input) {
        lines.insert(1, summary);
    }
    if let Some(summary) = agentic_scope_summary(&receipt.scan_input) {
        lines.insert(1, summary);
    }
    lines.push(supporting_context_summary(
        &receipt.scan_input,
        receipt.supporting_context.as_deref(),
    ));
    lines
}

fn scope_study_description(config: &BatchScanConfig) -> Option<Vec<String>> {
    let draft = config.study.scope_draft.as_ref()?;
    let mut lines = vec![format!("Selected boundaries: {} · {} fixed discovery jobs · {} worker(s)", draft.cases.len(), draft.job_count(), config.effective_workers),
        "Only these boundaries are planned. Shared dependencies provide context unless separately selected for discovery. No recursive subdivision or extra passes are authorized.".into()];
    for case in &draft.cases {
        let context = case.threat_model_ref.as_ref().map_or_else(
            || "inherit selected common context".into(),
            |value| {
                if value.is_null() {
                    "explicitly omitted".into()
                } else {
                    format!("exact override: {value}")
                }
            },
        );
        lines.push(format!(
            "{}: {} passes · context {context}",
            case.scope_id, case.passes
        ));
    }
    if let Some(receipt) = &config.study.scope_receipt {
        lines.push(format!("Frozen plan: {}", receipt.plan_sha256));
        lines.push(format!(
            "Unplanned boundaries: {}",
            receipt.scope_study.unplanned_scope_ids.join(", ")
        ));
        lines.push(format!(
            "Common context actually frozen: {}",
            receipt.scope_study.inherited_threat_model_ref
        ));
        lines.extend(receipt.scope_study.cases.iter().map(|case| {
            format!(
                "{} consumed context: {} · scope {}",
                case.label,
                context_reference_summary(&case.base_input),
                case.equivalence.components.scope_sha256
            )
        }));
    }
    Some(lines)
}

fn agentic_preparation_summary(input: &serde_json::Value) -> Option<String> {
    if !has_agentic_engine(input) {
        return None;
    }
    let (Some(files), Some(bytes)) = (
        input["maxInventoryFiles"].as_u64(),
        input["maxBytesPerFile"].as_u64(),
    ) else {
        return Some(
            "Agentic preparation limits were not recorded; inspect the producing run.".into(),
        );
    };
    Some(format!("Agentic preparation: snippet limit {files} · byte limit {bytes} before decoding. These bounds describe initial snippets; later agent reads are separate."))
}

fn has_agentic_engine(input: &serde_json::Value) -> bool {
    input["tasks"]
        .as_array()
        .is_some_and(|tasks| tasks.iter().any(|task| task == "agentic"))
}

fn agentic_scope_summary(input: &serde_json::Value) -> Option<String> {
    if !has_agentic_engine(input) {
        return None;
    }
    let scope = input["scanScopeRef"]["scopeId"].as_str()?;
    Some(format!("Exact read scope: {scope}. Read, list and search use accepted file membership. Shared files provide context only. Shell, writes and MCP tools are unavailable for this scoped job."))
}

pub(crate) fn supporting_context_lines(
    input: &serde_json::Value,
    text: Option<&str>,
) -> Vec<String> {
    if input.get("scanContextRef").is_none() {
        return vec![
            "Supporting context: legacy live selection. Prepare a new draft to freeze it.".into(),
        ];
    }
    let Some(text) = text else {
        return vec!["Supporting context: no supplemental text supplied to agentic discovery. Later context generation cannot add it to this plan.".into()];
    };
    let mut lines = vec!["Supporting context: exact frozen text for the agentic adapter. Other engines do not consume it.".into()];
    lines.extend(text.lines().map(str::to_owned));
    lines
}

pub(crate) fn allowance_status_lines(config: &BatchScanConfig) -> Vec<String> {
    let study = &config.study;
    if let Some(error) = &study.accounting_error {
        return failed_accounting_lines(config, error);
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

fn failed_accounting_lines(config: &BatchScanConfig, error: &str) -> Vec<String> {
    let mut lines = vec![
        format!("Investigation: {}", config.study.investigation_id),
        format!("Accounting unavailable: {error}"),
        "Work is blocked. r retries the read. Last-read counts are unverified until recovery."
            .into(),
    ];
    if let Some(allowance) = &config.study.allowance {
        lines.push(format!(
            "Last read: {} committed / {} total · {} unresolved",
            allowance.committed_calls,
            allowance.limits.max_provider_calls,
            allowance.unresolved_calls
        ));
        lines.push(format!(
            "Last read protected review: {} · allowance revision {}",
            allowance.protected_review_remaining(),
            allowance.revision
        ));
    }
    lines
}
