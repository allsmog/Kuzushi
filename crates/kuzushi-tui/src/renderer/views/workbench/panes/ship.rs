use super::*;
use crate::ui_view_models::{
    active_review_queue_mode, attack_tree, report_preview_model, workbench_export_command,
    workbench_report_command, ReportPreviewModel, ReviewQueueMode,
};
use kuzushi_core::{PersistedProofVerdict, WorkspaceExportFormat};
use ratatui::prelude::Line;

const REPORT_PREVIEW_ROW_LIMIT: usize = 5;
const WORKBENCH_MARKDOWN_BUNDLE_COMMAND: &str =
    "workspace export findings report-bundle markdown-bundle";

pub(in crate::renderer::views::workbench) fn ship_chain_lines(
    app: &ShellApp,
    width: usize,
) -> Vec<Line<'static>> {
    let hint = attack_tree(app).empty_hint;
    super::center::chain_pane_lines(app, hint.as_deref(), width)
}

pub(in crate::renderer::views::workbench) fn ship_patch_lines(
    app: &ShellApp,
    width: usize,
) -> Vec<Line<'static>> {
    let patchable = app
        .findings()
        .iter()
        .filter(|finding| {
            finding.verification.as_ref().is_some_and(|verification| {
                verification.proof_verdict == PersistedProofVerdict::Exploited
            })
        })
        .take(8)
        .collect::<Vec<_>>();
    if patchable.is_empty() {
        return pane_empty_state(
            "no patch queue",
            &["only empirically verified findings enter the patch queue."],
            &[("v", "run runtime verification for selected finding")],
        );
    }
    patchable
        .into_iter()
        .map(|finding| {
            Line::styled(
                fit(
                    &format!(
                        "{}  {}  patchable",
                        finding.fingerprint,
                        finding.severity.as_str()
                    ),
                    width,
                ),
                theme::primary(),
            )
        })
        .collect()
}

pub(in crate::renderer::views::workbench) fn ship_export_lines(
    app: &ShellApp,
    width: usize,
) -> Vec<Line<'static>> {
    let mode = active_review_queue_mode(app);
    let sarif_command = workbench_report_command(mode);
    let markdown_bundle_command = workbench_export_command(WORKBENCH_MARKDOWN_BUNDLE_COMMAND, mode);
    let preview = report_preview_model(app, WorkspaceExportFormat::Sarif, mode);
    let mut lines = vec![
        Line::styled("workspace export findings", theme::accent()),
        command_hint(sarif_command.as_ref(), "SARIF report", width),
        command_hint(markdown_bundle_command.as_ref(), "markdown bundle", width),
        blank(),
        Line::styled(
            fit(
                &format!(
                    "{} of {} findings in preview",
                    preview.counts.included_findings, preview.counts.total_findings
                ),
                width,
            ),
            theme::muted(),
        ),
    ];
    lines.extend(report_preview_lines(&preview, width));
    lines
}

fn report_preview_lines(preview: &ReportPreviewModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = report_preview_summary_lines(preview, width);
    if let Some(run_id) = preview.latest_run_id.as_deref() {
        lines.push(Line::styled(
            fit(&format!("latest run: {run_id}"), width),
            theme::muted(),
        ));
    }
    lines.push(Line::styled(
        fit(&format!("generated at: {}", preview.generated_at), width),
        theme::muted(),
    ));
    lines.push(report_preview_line(
        preview.preview_metadata.to_string(),
        width,
    ));
    if !preview.omitted_fields.is_empty() {
        lines.push(Line::styled(
            fit(
                &format!("format omits: {}", preview.omitted_fields.join(", ")),
                width,
            ),
            theme::warn(),
        ));
    }
    lines.extend(report_preview_row_lines(preview, width));
    lines
}

fn report_preview_summary_lines(preview: &ReportPreviewModel, width: usize) -> Vec<Line<'static>> {
    vec![
        report_preview_line(
            format!(
                "included decisions: {} terminal / {} open",
                preview.counts.included_terminal_decisions, preview.counts.included_open_decisions
            ),
            width,
        ),
        report_preview_line(
            format!(
                "workspace decisions: {} terminal / {} open",
                preview.counts.terminal_decisions, preview.counts.open_decisions
            ),
            width,
        ),
        report_preview_line(
            format!(
                "format:{} completeness:{}",
                preview.format, preview.completeness
            ),
            width,
        ),
        report_preview_line(
            format!("modes: {}", report_completeness_modes_label()),
            width,
        ),
    ]
}

fn report_preview_line(text: String, width: usize) -> Line<'static> {
    Line::styled(fit(&text, width), theme::muted())
}

fn report_preview_row_lines(preview: &ReportPreviewModel, width: usize) -> Vec<Line<'static>> {
    if preview.rows.is_empty() {
        return vec![report_preview_line(
            "preview rows: none selected by completeness mode".to_string(),
            width,
        )];
    }

    let mut lines = vec![Line::styled("preview rows", theme::accent())];
    lines.extend(
        preview
            .rows
            .iter()
            .take(REPORT_PREVIEW_ROW_LIMIT)
            .map(|row| report_preview_row_line(row, width)),
    );
    if preview.rows.len() > REPORT_PREVIEW_ROW_LIMIT {
        lines.push(report_preview_line(
            format!(
                "+{} more preview rows",
                preview.rows.len() - REPORT_PREVIEW_ROW_LIMIT
            ),
            width,
        ));
    }
    lines
}

fn report_preview_row_line(
    row: &crate::ui_view_models::ReportPreviewRow,
    width: usize,
) -> Line<'static> {
    let conflict = row
        .decision_conflict
        .as_deref()
        .map(|conflict| format!(" conflict:{conflict}"))
        .unwrap_or_default();
    let text = format!(
        "{} id:{} {} conf:{} decision:{}{} status:{} evidence:{} provenance:{} {} {}",
        row.alias,
        row.identity_label,
        row.severity,
        row.confidence,
        row.decision,
        conflict,
        row.lifecycle_status,
        row.evidence_state,
        row.provenance,
        row.location,
        row.title
    );
    Line::styled(fit(&text, width), theme::primary())
}

fn report_completeness_modes_label() -> String {
    [
        ReviewQueueMode::Open,
        ReviewQueueMode::Complete,
        ReviewQueueMode::All,
    ]
    .into_iter()
    .map(ReviewQueueMode::label)
    .collect::<Vec<_>>()
    .join(" ")
}

#[cfg(test)]
mod tests;
