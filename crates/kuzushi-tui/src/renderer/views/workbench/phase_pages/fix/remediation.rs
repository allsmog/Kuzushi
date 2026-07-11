use super::*;
use crate::ui_view_models::{
    FindingDetailModel, FixPhaseModel, PatchReviewModel, ThreatPatchCardModel,
};

pub(super) fn remediation_lines(model: &FixPhaseModel, width: usize) -> Vec<Line<'static>> {
    let mut details = match (&model.finding, &model.patch) {
        (_, Some(patch)) => patch_lines(patch, width),
        (Some(finding), None) => unstaged_patch_lines(finding, width),
        (None, None) => no_finding_lines(),
    };
    let mut lines = take_state_line(&mut details);
    lines.extend(export_command_lines(&model.export_command, width));
    lines.extend(details);
    if let Some(threat_patch) = model.threat_patch.as_ref() {
        lines.extend(threat_patch_lines(threat_patch, width));
    }
    lines
}

fn take_state_line(details: &mut Vec<Line<'static>>) -> Vec<Line<'static>> {
    if details.is_empty() {
        Vec::new()
    } else {
        vec![details.remove(0)]
    }
}

pub(super) fn compact_remediation_lines(model: &FixPhaseModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![compact_patch_state(model, width)];
    lines.extend(
        export_command_lines(&model.export_command, width)
            .into_iter()
            .take(1),
    );
    lines
}

fn compact_patch_state(model: &FixPhaseModel, width: usize) -> Line<'static> {
    match (&model.finding, &model.patch) {
        (_, Some(patch)) => staged_patch_state(patch),
        (Some(finding), None) => unstaged_patch_state(finding, width),
        (None, None) => Line::styled("no remediation selected", theme::muted()),
    }
}

fn staged_patch_state(patch: &PatchReviewModel) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{}  ", patch.alias), theme::label()),
        Span::styled("patch staged for review", theme::success()),
    ])
}

fn unstaged_patch_state(finding: &FindingDetailModel, width: usize) -> Line<'static> {
    Line::styled(
        fit(
            &format!(
                "{}  patch not staged",
                finding.alias.as_deref().unwrap_or("selected")
            ),
            width,
        ),
        theme::warn(),
    )
}

fn patch_lines(patch: &PatchReviewModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(vec![
        Span::styled(format!("{}  ", patch.alias), theme::label()),
        Span::styled("patch staged for review", theme::success()),
    ])];
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
    lines.push(Line::styled("  export findings as SARIF", theme::muted()));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_command_is_complete_at_reference_width() {
        let command = "findings export report.sarif sarif";
        let rendered = export_command_lines(command, 120)
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(rendered.contains(command));
    }
}
