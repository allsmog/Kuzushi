use super::*;
use crate::ui_view_models::{FindingDetailModel, ProofReplayModel, ProofTier};

pub(super) fn finding_header_lines(
    finding: &FindingDetailModel,
    width: usize,
) -> Vec<Line<'static>> {
    vec![
        finding_identity_line(finding, width),
        Line::styled(fit(&finding.title, width), theme::heading()),
        Line::styled(fit(&finding.location, width), theme::muted()),
        finding_status_line(finding, width),
        finding_next_line(finding, width),
    ]
}

fn finding_identity_line(finding: &FindingDetailModel, width: usize) -> Line<'static> {
    let alias = finding.alias.as_deref().unwrap_or("selected");
    let proof = format!(
        "{} {} · {} · {} source(s)  ",
        finding.proof_marker,
        finding.proof_meter,
        finding.proof_confidence_label,
        finding.source_count
    );
    Line::from(vec![
        Span::styled(format!("{alias}  "), theme::label()),
        Span::styled(
            format!("{}  ", finding.severity_label.to_ascii_uppercase()),
            theme::severity_tone(finding.severity_tone),
        ),
        Span::styled(
            proof,
            theme::proof_confidence_tone(finding.proof_confidence),
        ),
        Span::styled(
            fit(&finding.lifecycle_status, width.saturating_sub(28)),
            theme::muted(),
        ),
    ])
}

fn finding_status_line(finding: &FindingDetailModel, width: usize) -> Line<'static> {
    let status = format!(
        "{} · decision:{} · {}",
        finding.lifecycle_status, finding.decision, finding.evidence_state
    );
    Line::from(vec![
        Span::styled("STATUS ", theme::label()),
        Span::styled(fit(&status, width.saturating_sub(7)), theme::primary()),
    ])
}

fn finding_next_line(finding: &FindingDetailModel, width: usize) -> Line<'static> {
    let next = finding
        .next_command
        .as_deref()
        .map(|command| format!("{} · {command}", finding.next_action_label))
        .unwrap_or_else(|| format!("{} · {}", finding.next_action_label, finding.next_detail));
    Line::from(vec![
        Span::styled("NEXT   ", theme::warn()),
        Span::styled(fit(&next, width.saturating_sub(7)), theme::accent()),
    ])
}

pub(super) fn proof_ladder_lines(
    finding: &FindingDetailModel,
    proof: Option<&ProofReplayModel>,
    width: usize,
) -> Vec<Line<'static>> {
    let (source, runtime) = proof_rungs(finding.proof_tier);
    let mut lines = vec![
        proof_rung("1", true, "signal captured", width),
        proof_rung("2", source, &finding.static_proof_label, width),
        proof_rung(
            "3",
            runtime,
            proof
                .map(|proof| proof.verdict.as_str())
                .unwrap_or("runtime proof pending"),
            width,
        ),
        Line::styled(
            fit(
                &format!(
                    "current {} {} · {} source(s)",
                    finding.proof_meter, finding.proof_label, finding.source_count
                ),
                width,
            ),
            theme::proof_confidence_tone(finding.proof_confidence),
        ),
    ];
    if proof.is_some_and(|proof| proof.requires_revalidation) {
        lines.push(Line::styled(
            fit("⚠ proof belongs to a prior observation · revalidate", width),
            theme::warn(),
        ));
    }
    lines
}

fn proof_rungs(tier: ProofTier) -> (bool, bool) {
    match tier {
        ProofTier::RuntimeVerified => (true, true),
        ProofTier::StaticLinked => (true, false),
        ProofTier::Suspected => (false, false),
        ProofTier::Rejected => (false, false),
    }
}

fn proof_rung(stage: &str, complete: bool, label: &str, width: usize) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{} {stage} ", if complete { "●" } else { "○" }),
            if complete {
                theme::success()
            } else {
                theme::muted()
            },
        ),
        Span::styled(
            fit(label, width.saturating_sub(4)),
            if complete {
                theme::primary()
            } else {
                theme::muted()
            },
        ),
    ])
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
    runtime_proof_lines(proof, finding, width)
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
        verification_command_line(finding, width),
    ]
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
