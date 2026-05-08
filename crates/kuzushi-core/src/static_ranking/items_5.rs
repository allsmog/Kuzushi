use super::prelude::*;
use super::*;

pub(crate) fn privilege_boundary_score(
    corpus: &str,
    attack_surface: Option<&AttackSurfaceMap>,
    finding: &Finding,
    reasons: &mut Vec<String>,
) -> i32 {
    let mut score = if contains_any(
        corpus,
        &["auth", "admin", "role", "permission", "tenant", "privilege"],
    ) {
        12
    } else {
        0
    };

    if let Some(surface_map) = attack_surface {
        if surface_map.surfaces.iter().any(|surface| {
            surface.path == finding.file_path
                && matches!(surface.kind, AttackSurfaceKind::AuthBoundary)
        }) {
            score = score.max(16);
        }
        if surface_map.surfaces.iter().any(|surface| {
            surface.path == finding.file_path && surface.boundary.as_deref() == Some("public_http")
        }) {
            score = score.max(10);
        }
    }

    if score > 0 {
        reasons.push("privilege_or_trust_boundary".to_string());
    }
    score
}

pub(crate) fn sanitizer_absence_score(
    corpus: &str,
    evidence_nodes: &[StaticEvidenceNode],
    proof_state: Option<StaticProofState>,
    reasons: &mut Vec<String>,
) -> i32 {
    if proof_state == Some(StaticProofState::StaticallyRejected)
        || contains_any(
            corpus,
            &["sanitizer assessment: present", "sanitized_by", "sanitized"],
        )
        || evidence_nodes
            .iter()
            .any(|node| node.kind == StaticEvidenceNodeKind::Sanitizer)
    {
        reasons.push("sanitizer_or_guard_present".to_string());
        return -20;
    }
    if contains_any(
        corpus,
        &[
            "sanitizer assessment: absent",
            "sanitizer absent",
            "guard assessment: absent",
            "missing guard",
            "unsanitized",
        ],
    ) {
        reasons.push("sanitizer_or_guard_absent".to_string());
        return 14;
    }
    if matches!(
        proof_state,
        Some(StaticProofState::SourceSinkLinked | StaticProofState::SanitizerChecked)
    ) {
        return 6;
    }
    0
}

pub(crate) fn framework_context_score(
    corpus: &str,
    attack_surface: Option<&AttackSurfaceMap>,
    finding: &Finding,
) -> i32 {
    if let Some(surface_map) = attack_surface {
        if surface_map.surfaces.iter().any(|surface| {
            surface.path == finding.file_path
                && surface
                    .framework
                    .as_ref()
                    .is_some_and(|framework| !framework.trim().is_empty())
        }) {
            return 8;
        }
    }
    if contains_any(
        corpus,
        &[
            "express", "flask", "fastapi", "django", "gin", "actix", "rocket",
        ],
    ) {
        6
    } else {
        0
    }
}
