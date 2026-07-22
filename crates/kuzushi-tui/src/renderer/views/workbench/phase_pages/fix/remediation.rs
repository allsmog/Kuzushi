use super::*;
use crate::ui_view_models::{
    FindingDetailModel, FixPhaseModel, PatchReviewModel, RemediationLifecycleModel,
    RemediationLifecycleStage, RemediationLoadState, ThreatPatchCardModel,
};

pub(super) fn remediation_lines(model: &FixPhaseModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = selection_disclosure_lines(model.selection_disclosure.as_ref(), width);
    lines.extend(lifecycle_lines(&model.remediation, width));
    lines.extend(approval_action_lines(&model.remediation, width));
    lines.extend(export_command_lines(&model.export_command, width));
    lines.extend(remediation_detail_lines(model, width));
    if let Some(threat_patch) = model.threat_patch.as_ref() {
        lines.extend(threat_patch_lines(threat_patch, width));
    }
    lines
}

pub(super) fn compact_remediation_lines(model: &FixPhaseModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = selection_disclosure_lines(model.selection_disclosure.as_ref(), width);
    lines.extend(
        lifecycle_lines(&model.remediation, width)
            .into_iter()
            .take(2),
    );
    lines.extend(approval_action_lines(&model.remediation, width));
    lines.extend(
        export_command_lines(&model.export_command, width)
            .into_iter()
            .take(1),
    );
    lines
}

fn approval_action_lines(model: &RemediationLifecycleModel, width: usize) -> Vec<Line<'static>> {
    if model.stage != RemediationLifecycleStage::StagedForApproval {
        return Vec::new();
    }
    let (alternate_lead, alternate_actions) = if width < 48 {
        ("OR ", "patch reject · patch regen")
    } else {
        ("OR     ", "patch reject (discard) · patch regen")
    };
    [
        ("NEXT   ", "patch apply · write reviewed diff"),
        (alternate_lead, alternate_actions),
    ]
    .into_iter()
    .map(|(lead, action)| {
        Line::from(vec![
            Span::styled(lead, theme::warn()),
            Span::styled(
                fit(action, width.saturating_sub(display_width(lead))),
                theme::accent(),
            ),
        ])
    })
    .collect()
}

fn remediation_detail_lines(model: &FixPhaseModel, width: usize) -> Vec<Line<'static>> {
    if matches!(
        model.remediation.load_state,
        RemediationLoadState::Loading | RemediationLoadState::Failed
    ) {
        return Vec::new();
    }
    match (&model.finding, &model.patch, model.remediation.stage) {
        (_, Some(patch), _) => patch_lines(patch, width),
        (Some(_), None, RemediationLifecycleStage::DraftAvailable) => Vec::new(),
        (Some(_), None, stage) if lifecycle_receipt_stage(stage) => Vec::new(),
        (Some(finding), None, _) => unstaged_patch_lines(finding, width),
        (None, None, _) => no_finding_lines(),
    }
}

fn lifecycle_receipt_stage(stage: RemediationLifecycleStage) -> bool {
    !matches!(
        stage,
        RemediationLifecycleStage::NotDrafted
            | RemediationLifecycleStage::DraftAvailable
            | RemediationLifecycleStage::StagedForApproval
    )
}

fn lifecycle_lines(model: &RemediationLifecycleModel, width: usize) -> Vec<Line<'static>> {
    if model.load_state == RemediationLoadState::Loading {
        return vec![Line::from(vec![
            Span::styled("STATE  ", theme::label()),
            Span::styled("loading remediation truth", theme::muted()),
        ])];
    }
    if model.load_state == RemediationLoadState::Failed {
        let mut lines = vec![Line::from(vec![
            Span::styled("STATE  ", theme::label()),
            Span::styled("remediation truth unavailable", theme::warn()),
        ])];
        append_optional_detail(&mut lines, "error", model.load_error.as_deref(), width);
        return lines;
    }
    let mut lines = vec![Line::from(vec![
        Span::styled("STATE  ", theme::label()),
        Span::styled(model.stage.label(), lifecycle_style(model.stage)),
    ])];
    append_receipt_identity(&mut lines, model, width);
    append_touched_paths(&mut lines, &model.touched_paths, width);
    append_optional_detail(&mut lines, "outcome", model.detail.as_deref(), width);
    append_optional_detail(&mut lines, "updated", model.updated_at.as_deref(), width);
    append_optional_detail(&mut lines, "error", model.load_error.as_deref(), width);
    if let Some(command) = model.reverify_command.as_deref() {
        lines.push(reverify_line(model, command, width));
    }
    lines
}

fn reverify_line(model: &RemediationLifecycleModel, command: &str, width: usize) -> Line<'static> {
    let lead = model
        .reverify_control_hint
        .as_deref()
        .map(|hint| format!("▸ {hint} re-verify · "))
        .unwrap_or_else(|| "▸ re-verify · ".to_string());
    let command_width = width.saturating_sub(display_width(&lead));
    Line::from(vec![
        Span::styled(lead, theme::warn()),
        Span::styled(fit(command, command_width), theme::accent()),
    ])
}

fn append_receipt_identity(
    lines: &mut Vec<Line<'static>>,
    model: &RemediationLifecycleModel,
    width: usize,
) {
    append_optional_detail(lines, "application", model.application_id.as_deref(), width);
    append_optional_detail(lines, "patch run", model.patch_run_id.as_deref(), width);
    append_optional_detail(lines, "diff hash", model.diff_hash.as_deref(), width);
    append_optional_detail(
        lines,
        "reverify run",
        model.reverify_run_id.as_deref(),
        width,
    );
}

fn append_touched_paths(lines: &mut Vec<Line<'static>>, paths: &[String], width: usize) {
    for (index, path) in paths.iter().enumerate() {
        let label = if index == 0 { "touched" } else { "" };
        lines.extend(wrapped_detail(label, path, width));
    }
}

fn append_optional_detail(
    lines: &mut Vec<Line<'static>>,
    label: &str,
    value: Option<&str>,
    width: usize,
) {
    if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
        lines.extend(wrapped_detail(label, value, width));
    }
}

fn lifecycle_style(stage: RemediationLifecycleStage) -> ratatui::style::Style {
    match stage {
        RemediationLifecycleStage::Verified => theme::success(),
        RemediationLifecycleStage::Applied
        | RemediationLifecycleStage::Applying
        | RemediationLifecycleStage::ReverifyRunning
        | RemediationLifecycleStage::DraftAvailable
        | RemediationLifecycleStage::StagedForApproval => theme::accent(),
        RemediationLifecycleStage::StillVulnerable
        | RemediationLifecycleStage::NotRediscovered
        | RemediationLifecycleStage::Inconclusive
        | RemediationLifecycleStage::ApplyFailed
        | RemediationLifecycleStage::Failed
        | RemediationLifecycleStage::Interrupted
        | RemediationLifecycleStage::ChangedSinceApply
        | RemediationLifecycleStage::PriorFindingGeneration => theme::warn(),
        RemediationLifecycleStage::NotDrafted => theme::muted(),
    }
}

fn patch_lines(patch: &PatchReviewModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![Line::styled(
        format!("{} · pending reviewed diff", patch.alias),
        theme::label(),
    )];
    lines.extend(wrapped_detail("rationale", &patch.rationale, width));
    if let Some(side_effect) = patch.side_effect.as_deref() {
        lines.extend(wrapped_detail("side effect", side_effect, width));
    }
    lines.extend(patch.tests.iter().take(3).map(|test| {
        Line::styled(
            fit(&format!("✓ {} · {}", test.name, test.blurb), width),
            theme::success(),
        )
    }));
    if let Some(guardrail) = patch.guardrail.as_deref() {
        lines.extend(wrapped_detail("guardrail", guardrail, width));
    }
    lines
}

fn unstaged_patch_lines(finding: &FindingDetailModel, width: usize) -> Vec<Line<'static>> {
    let alias = finding.alias.as_deref().unwrap_or(&finding.fingerprint);
    let mut lines = vec![Line::from(vec![
        Span::styled(format!("{alias}  "), theme::label()),
        Span::styled("patch not staged", theme::warn()),
    ])];
    if let Some(hint) = finding.remediation_hint.as_deref() {
        lines.extend(wrapped_detail("fix", hint, width));
    }
    lines.push(Line::from(vec![
        Span::styled("▸ ", theme::warn()),
        Span::styled(format!("patch {alias}"), theme::accent()),
        Span::styled("  draft a reviewed patch", theme::muted()),
    ]));
    lines
}

fn no_finding_lines() -> Vec<Line<'static>> {
    empty_state_panel(
        "no remediation selected",
        &["select a finding before drafting a patch"],
        &[("2", "open Hunt and choose a finding")],
    )
}

fn threat_patch_lines(model: &ThreatPatchCardModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![Line::styled(
        fit(
            &format!(
                "threat-model patch · {} · {} top-level changes",
                model.goal, model.top_level_keys
            ),
            width,
        ),
        theme::accent(),
    )];
    lines.extend(wrapped_detail("summary", &model.summary, width));
    if !model.unsupported.is_empty() {
        lines.push(Line::styled(
            fit(
                &format!("unsupported: {}", model.unsupported.join(", ")),
                width,
            ),
            theme::warn(),
        ));
    }
    lines
}

fn wrapped_detail(label: &str, value: &str, width: usize) -> Vec<Line<'static>> {
    let prefix = format!("{label}: ");
    let indent = " ".repeat(prefix.len());
    wrap_text(value, width.saturating_sub(prefix.len()).max(12))
        .into_iter()
        .enumerate()
        .map(|(index, chunk)| {
            let lead = if index == 0 {
                prefix.clone()
            } else {
                indent.clone()
            };
            Line::from(vec![
                Span::styled(lead, theme::muted()),
                Span::styled(chunk, theme::primary()),
            ])
        })
        .collect()
}

fn export_command_lines(command: &str, width: usize) -> Vec<Line<'static>> {
    let budget = width.saturating_sub(2).max(12);
    let mut lines = wrap_text(command, budget)
        .into_iter()
        .enumerate()
        .map(|(index, chunk)| {
            let lead = if index == 0 { "▸ " } else { "  " };
            Line::from(vec![
                Span::styled(lead, theme::warn()),
                Span::styled(chunk, theme::label()),
            ])
        })
        .collect::<Vec<_>>();
    lines.push(Line::styled(
        "  choose format, completeness, and destination",
        theme::muted(),
    ));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remediation_model(
        load_state: RemediationLoadState,
        load_error: Option<&str>,
    ) -> RemediationLifecycleModel {
        RemediationLifecycleModel {
            load_state,
            stage: RemediationLifecycleStage::NotDrafted,
            application_id: None,
            patch_run_id: None,
            diff_hash: None,
            touched_paths: Vec::new(),
            reverify_run_id: None,
            detail: None,
            updated_at: None,
            reverify_command: None,
            reverify_control_hint: None,
            load_error: load_error.map(str::to_string),
        }
    }

    #[test]
    fn report_exit_command_is_complete_at_reference_width() {
        let command = "report";
        let rendered = export_command_lines(command, 120)
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(rendered.contains(command));
    }

    #[test]
    fn loading_truth_does_not_claim_that_no_patch_was_drafted() {
        let rendered = lifecycle_lines(&remediation_model(RemediationLoadState::Loading, None), 80)
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(rendered.contains("loading remediation truth"));
        assert!(!rendered.contains("not drafted"));
    }

    #[test]
    fn failed_truth_surfaces_the_reader_error() {
        let rendered = lifecycle_lines(
            &remediation_model(
                RemediationLoadState::Failed,
                Some("database is unavailable"),
            ),
            80,
        )
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");

        assert!(rendered.contains("remediation truth unavailable"));
        assert!(rendered.contains("database is unavailable"));
    }

    #[test]
    fn staged_patch_names_each_available_approval_action() {
        let mut model = remediation_model(RemediationLoadState::Ready, None);
        model.stage = RemediationLifecycleStage::StagedForApproval;

        for width in [31, 80] {
            let rendered = approval_action_lines(&model, width)
                .into_iter()
                .map(|line| line.to_string())
                .collect::<String>();

            assert!(rendered.contains("patch apply"), "{width}: {rendered}");
            assert!(rendered.contains("patch reject"), "{width}: {rendered}");
            assert!(rendered.contains("patch regen"), "{width}: {rendered}");
        }
    }

    #[test]
    fn reverify_line_discloses_mode_entry_before_the_navigation_key() {
        let mut model = remediation_model(RemediationLoadState::Ready, None);
        model.reverify_command =
            Some("run patch:reverify {\"applicationId\":\"application-1\"}".to_string());
        model.reverify_control_hint = Some("Esc then v".to_string());

        let rendered = lifecycle_lines(&model, 120)
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(rendered.contains("▸ Esc then v re-verify · run patch:reverify"));
        assert!(!rendered.contains("▸ v  re-verify"));
    }
}
