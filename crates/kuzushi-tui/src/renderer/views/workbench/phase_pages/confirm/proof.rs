use super::*;
use crate::ui_view_models::{FindingDetailModel, ProofReplayModel};

pub(super) fn finding_header_lines(
    finding: &FindingDetailModel,
    width: usize,
) -> Vec<Line<'static>> {
    let alias = finding.alias.as_deref().unwrap_or("selected");
    vec![
        Line::from(vec![
            Span::styled(format!("{alias}  "), theme::label()),
            Span::styled(
                format!("{}  ", finding.severity_label.to_ascii_uppercase()),
                theme::severity_tone(finding.severity_tone),
            ),
            Span::styled(
                format!("{} {}  ", finding.proof_marker, finding.proof_label),
                theme::proof_confidence_tone(finding.proof_confidence),
            ),
            Span::styled(
                fit(&finding.lifecycle_status, width.saturating_sub(28)),
                theme::muted(),
            ),
        ]),
        Line::styled(fit(&finding.title, width), theme::heading()),
        Line::styled(fit(&finding.location, width), theme::muted()),
    ]
}

pub(super) fn proof_title(proof: Option<&ProofReplayModel>) -> &'static str {
    if proof.is_some_and(ProofReplayModel::has_replay) {
        "PROOF · REPLAY"
    } else {
        "PROOF"
    }
}

pub(super) fn proof_lines(
    proof: Option<&ProofReplayModel>,
    finding: &FindingDetailModel,
    width: usize,
) -> Vec<Line<'static>> {
    let report_command = (width >= 44).then_some(crate::ui_view_models::WORKBENCH_REPORT_COMMAND);
    let mut lines = runtime_proof_lines(proof, finding, width);
    lines.push(blank());
    lines.push(divider(
        "FINDING STATE",
        width.min(u16::MAX as usize) as u16,
    ));
    lines.extend(super::super::super::detail_pane::detail_pane_lines(
        &Some(finding.clone()),
        width,
        report_command,
    ));
    lines
}

pub(super) fn compact_proof_lines(
    proof: Option<&ProofReplayModel>,
    finding: &FindingDetailModel,
    width: usize,
) -> Vec<Line<'static>> {
    let Some(proof) = proof else {
        return compact_missing_runtime_proof_lines(finding, width);
    };
    let mut lines = proof_summary_lines(proof, width)
        .into_iter()
        .take(1)
        .collect::<Vec<_>>();
    lines.push(compact_decision_line(finding, width));
    lines.push(verification_command_line(finding, width));
    append_replay_provenance(&mut lines, proof, width);
    lines
}

fn compact_missing_runtime_proof_lines(
    finding: &FindingDetailModel,
    width: usize,
) -> Vec<Line<'static>> {
    vec![
        Line::styled("runtime proof has not run", theme::warn()),
        compact_decision_line(finding, width),
        verification_command_line(finding, width),
    ]
}

fn compact_decision_line(finding: &FindingDetailModel, width: usize) -> Line<'static> {
    let decision = finding.decision.replace('_', " ");
    Line::styled(fit(&format!("decision: {decision}"), width), theme::label())
}

fn runtime_proof_lines(
    proof: Option<&ProofReplayModel>,
    finding: &FindingDetailModel,
    width: usize,
) -> Vec<Line<'static>> {
    let Some(proof) = proof else {
        return missing_runtime_proof_lines(finding, width);
    };
    let mut lines = proof_summary_lines(proof, width);
    append_replay_provenance(&mut lines, proof, width);
    lines.push(verification_command_line(finding, width));
    append_proof_metadata(&mut lines, proof, width);
    append_proof_notes(&mut lines, proof, width);
    lines
}

fn verification_command_line(finding: &FindingDetailModel, width: usize) -> Line<'static> {
    let command = format!("verify {}", finding.alias.as_deref().unwrap_or("selected"));
    command_line(&command, "recheck", width)
}

fn missing_runtime_proof_lines(finding: &FindingDetailModel, width: usize) -> Vec<Line<'static>> {
    vec![
        Line::styled("runtime proof has not run", theme::warn()),
        Line::styled(fit(&finding.static_proof_label, width), theme::primary()),
        Line::styled(fit(&finding.runtime_explanation, width), theme::muted()),
        command_line(
            finding.next_command.as_deref().unwrap_or("v"),
            "collect proof",
            width,
        ),
    ]
}

fn proof_summary_lines(proof: &ProofReplayModel, width: usize) -> Vec<Line<'static>> {
    vec![
        Line::from(vec![
            Span::styled(
                format!("{}  ", proof.verdict),
                proof_verdict_style(&proof.verdict),
            ),
            Span::styled(
                format!("L{} · {}", proof.proof_level, proof.backend),
                theme::primary(),
            ),
        ]),
        Line::styled(
            fit(
                &format!("{}ms · ${:.4}", proof.duration_ms, proof.cost_usd),
                width,
            ),
            theme::muted(),
        ),
    ]
}

fn append_proof_metadata(lines: &mut Vec<Line<'static>>, proof: &ProofReplayModel, width: usize) {
    if proof.requires_revalidation {
        lines.push(Line::styled(
            fit("prior-observation proof · revalidate this scan", width),
            theme::warn(),
        ));
    }
    append_optional(lines, "language", proof.language.as_deref(), width);
    append_optional(lines, "harness", proof.harness_path.as_deref(), width);
    append_optional(lines, "evidence", proof.crash_evidence.as_deref(), width);
}

fn append_proof_notes(lines: &mut Vec<Line<'static>>, proof: &ProofReplayModel, width: usize) {
    lines.extend(
        proof
            .notes
            .iter()
            .take(4)
            .map(|note| Line::styled(fit(&format!("✓ {note}"), width), theme::success())),
    );
}

fn append_replay_provenance(
    lines: &mut Vec<Line<'static>>,
    proof: &ProofReplayModel,
    width: usize,
) {
    match (
        proof.replay_run_id.as_deref(),
        proof.provenance_run_id.as_deref(),
    ) {
        (Some(run_id), _) => lines.push(command_line(
            &format!("replay {run_id}"),
            "open trace",
            width,
        )),
        (None, Some(run_id)) => lines.push(Line::styled(
            fit(&format!("run {run_id} · trace unavailable"), width),
            theme::muted(),
        )),
        (None, None) => {}
    }
}

fn append_optional(lines: &mut Vec<Line<'static>>, label: &str, value: Option<&str>, width: usize) {
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        lines.push(Line::styled(
            fit(&format!("{label}: {value}"), width),
            theme::muted(),
        ));
    }
}

fn command_line(command: &str, label: &str, width: usize) -> Line<'static> {
    Line::from(vec![
        Span::styled("▸ ", theme::warn()),
        Span::styled(
            fit(command, width.saturating_sub(label.len() + 4)),
            theme::label(),
        ),
        Span::styled(format!("  {label}"), theme::muted()),
    ])
}

fn proof_verdict_style(verdict: &str) -> ratatui::style::Style {
    match verdict {
        "exploited" => theme::success(),
        "not_reproduced" => theme::warn(),
        _ => theme::danger(),
    }
}
