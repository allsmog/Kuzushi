use super::*;

pub(crate) fn severity_score_str(severity: &str) -> i32 {
    match severity {
        "critical" => 30,
        "high" => 20,
        "medium" => 10,
        "low" => 4,
        "info" => 1,
        _ => 0,
    }
}

pub(crate) fn static_proof_score(state: Option<StaticProofState>) -> i32 {
    match state {
        Some(StaticProofState::StaticallyConfirmed) => 32,
        Some(StaticProofState::SanitizerChecked) => 24,
        Some(StaticProofState::SourceSinkLinked) => 20,
        Some(StaticProofState::CodeCited) => 8,
        Some(StaticProofState::NeedsRuntimeEvidence) => 3,
        Some(StaticProofState::SignalOnly) | None => 0,
        Some(StaticProofState::StaticallyRejected) => -100,
    }
}

pub(crate) fn attack_surface_score(
    finding: &Finding,
    attack_surface: Option<&AttackSurfaceMap>,
    evidence_nodes: &[StaticEvidenceNode],
    reasons: &mut Vec<String>,
) -> i32 {
    let Some(surface_map) = attack_surface else {
        return 0;
    };
    let mut best = 0;
    for surface in &surface_map.surfaces {
        if surface_matches_finding(surface, finding, evidence_nodes) {
            let score = match surface.kind {
                AttackSurfaceKind::HttpRoute | AttackSurfaceKind::RpcHandler => 24,
                AttackSurfaceKind::CliEntrypoint => 18,
                AttackSurfaceKind::FileUploadParsePath => 20,
                AttackSurfaceKind::DeserializationPoint => 18,
                AttackSurfaceKind::DbQueryBoundary
                | AttackSurfaceKind::CommandExecutionBoundary => 16,
                AttackSurfaceKind::AuthBoundary => 14,
                AttackSurfaceKind::BackgroundJob => 10,
            };
            if score > best {
                best = score;
            }
        }
    }
    if best > 0 {
        reasons.push("attack_surface_reachable".to_string());
    }
    best
}

pub(crate) fn surface_matches_finding(
    surface: &AttackSurface,
    finding: &Finding,
    evidence_nodes: &[StaticEvidenceNode],
) -> bool {
    if surface.path != finding.file_path
        && !evidence_nodes
            .iter()
            .any(|node| node.source_path.as_deref() == Some(surface.path.as_str()))
    {
        return false;
    }

    let Some(surface_line) = surface.line else {
        return true;
    };
    let finding_end = finding.end_line.unwrap_or(finding.start_line);
    if lines_overlap_or_near(surface_line, finding.start_line, finding_end, 12) {
        return true;
    }
    evidence_nodes.iter().any(|node| {
        node.source_path.as_deref() == Some(surface.path.as_str())
            && node.start_line.is_some_and(|line| {
                lines_overlap_or_near(surface_line, line, node.end_line.unwrap_or(line), 12)
            })
    })
}

pub(crate) fn lines_overlap_or_near(anchor: u32, start: u32, end: u32, window: u32) -> bool {
    let low = start.saturating_sub(window);
    let high = end.saturating_add(window);
    anchor >= low && anchor <= high
}
