use super::*;

pub(crate) fn privilege_boundary_score(
    corpus: &str,
    attack_surface: Option<&AttackSurfaceMap>,
    finding: &Finding,
    reasons: &mut Vec<String>,
) -> i32 {
    let score = privilege_keyword_score(corpus).max(privilege_surface_score(attack_surface, finding));

    record_privilege_reason(score, reasons);
    score
}

fn privilege_keyword_score(corpus: &str) -> i32 {
    if contains_any(corpus, PRIVILEGE_BOUNDARY_KEYWORDS) {
        12
    } else {
        0
    }
}

fn privilege_surface_score(attack_surface: Option<&AttackSurfaceMap>, finding: &Finding) -> i32 {
    let Some(surface_map) = attack_surface else {
        return 0;
    };
    matching_surface_score(surface_map, finding, is_privilege_surface, 16).max(
        matching_surface_score(surface_map, finding, is_public_http_surface, 10),
    )
}

fn matching_surface_score(
    surface_map: &AttackSurfaceMap,
    finding: &Finding,
    predicate: fn(&AttackSurface) -> bool,
    score: i32,
) -> i32 {
    if surface_map
        .surfaces
        .iter()
        .any(|surface| surface.path == finding.file_path && predicate(surface))
    {
        score
    } else {
        0
    }
}

fn is_privilege_surface(surface: &AttackSurface) -> bool {
    is_privilege_surface_kind(surface.kind)
}

fn is_privilege_surface_kind(kind: AttackSurfaceKind) -> bool {
    matches!(
        kind,
        AttackSurfaceKind::AuthBoundary
            | AttackSurfaceKind::SessionStateBoundary
            | AttackSurfaceKind::RequestTrustBoundary
            | AttackSurfaceKind::TenantIsolationBoundary
    )
}

fn is_public_http_surface(surface: &AttackSurface) -> bool {
    surface.boundary.as_deref() == Some("public_http")
}

fn record_privilege_reason(score: i32, reasons: &mut Vec<String>) {
    if score > 0 {
        reasons.push("privilege_or_trust_boundary".to_string());
    }
}

const PRIVILEGE_BOUNDARY_KEYWORDS: &[&str] = &[
    "auth",
    "admin",
    "role",
    "permission",
    "tenant",
    "privilege",
    "session",
    "cookie",
    "jwt",
    "token",
];

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
