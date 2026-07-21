//! Result-fidelity contracts enforced in code at write time.
//!
//! Three rules, one chokepoint (imports and the fleet corpus call these;
//! consumers never re-derive them):
//! - **Derived severity.** A finding's severity ceiling follows mechanically
//!   from its attacker precondition. Claims above the ceiling are capped and
//!   the cap is recorded — never re-litigated in prompts or review.
//! - **Cluster identity.** Cross-run/cross-target clustering keys on file +
//!   line window (±15, span-extended). Free-text identity strings churn
//!   run-to-run and are never a clustering input.
//! - **Closed class enum.** `class` is constrained at ingest; unrecognized
//!   labels are inferred from CWE/keywords and flagged `class-inferred`,
//!   never silently rewritten.

use crate::findings::Severity;
use serde::Serialize;

/// Closed attacker-precondition vocabulary (weakest credible attacker that
/// can reach the flaw). Unknown strings parse to `None` — the caller keeps
/// the claim unmodified but uncapped severity is then its own risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Precondition {
    UnauthNetwork,
    ProtectedHost,
    CrossTenant,
    PairedPeer,
    AuthedRole,
    LocalUid,
    Rksupport,
    Mitm,
    Insider,
    SupplyChain,
    Physical,
}

impl Precondition {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "unauth-network" | "unauthenticated-network" | "unauth" => Some(Self::UnauthNetwork),
            "protected-host" => Some(Self::ProtectedHost),
            "cross-tenant" => Some(Self::CrossTenant),
            "paired-peer" => Some(Self::PairedPeer),
            "authed-role" | "authenticated" | "authed" => Some(Self::AuthedRole),
            "local-uid" | "local" => Some(Self::LocalUid),
            "rksupport" => Some(Self::Rksupport),
            "mitm" => Some(Self::Mitm),
            "insider" => Some(Self::Insider),
            "supply-chain" => Some(Self::SupplyChain),
            "physical" => Some(Self::Physical),
            _ => None,
        }
    }

    /// Mechanical severity ceiling. Pre-auth network and tenant-boundary
    /// breaks (plus protected-host primitives) can justify critical;
    /// peer/MitM/credentialed/local paths cap at high; physical caps at
    /// medium.
    pub fn severity_ceiling(self) -> Severity {
        match self {
            Self::UnauthNetwork | Self::CrossTenant | Self::ProtectedHost => Severity::Critical,
            Self::PairedPeer
            | Self::AuthedRole
            | Self::LocalUid
            | Self::Rksupport
            | Self::Mitm
            | Self::Insider
            | Self::SupplyChain => Severity::High,
            Self::Physical => Severity::Medium,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnauthNetwork => "unauth-network",
            Self::ProtectedHost => "protected-host",
            Self::CrossTenant => "cross-tenant",
            Self::PairedPeer => "paired-peer",
            Self::AuthedRole => "authed-role",
            Self::LocalUid => "local-uid",
            Self::Rksupport => "rksupport",
            Self::Mitm => "mitm",
            Self::Insider => "insider",
            Self::SupplyChain => "supply-chain",
            Self::Physical => "physical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CappedSeverity {
    pub severity: Severity,
    /// True when the claim exceeded the precondition ceiling and was
    /// lowered. Recorded, counted, and visible — the ceiling is code.
    pub tier_capped: bool,
}

pub fn enforce_severity_ceiling(
    claimed: Severity,
    precondition: Option<Precondition>,
) -> CappedSeverity {
    let Some(precondition) = precondition else {
        return CappedSeverity {
            severity: claimed,
            tier_capped: false,
        };
    };
    let ceiling = precondition.severity_ceiling();
    if severity_rank(claimed) > severity_rank(ceiling) {
        CappedSeverity {
            severity: ceiling,
            tier_capped: true,
        }
    } else {
        CappedSeverity {
            severity: claimed,
            tier_capped: false,
        }
    }
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Info => 1,
        Severity::Unknown => 0,
    }
}

/// Closed vulnerability-class vocabulary for cross-target aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingClass {
    MemOobWrite,
    MemOobRead,
    MemUseAfterFree,
    MemDoubleFree,
    MemUninit,
    IntOverflow,
    Injection,
    PathTraversal,
    Ssrf,
    Xxe,
    Deserialization,
    AuthBypass,
    AuthzMissing,
    CryptoMisuse,
    SecretExposure,
    RaceCondition,
    Dos,
    InfoLeak,
    LogicError,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClassifiedFinding {
    pub class: FindingClass,
    /// True when the class came from CWE/keyword inference rather than an
    /// exact enum label — surfaced as a `class-inferred` quality flag.
    pub inferred: bool,
}

/// Constrain a free-text class/CWE/title triple onto the closed enum.
pub fn classify(class_label: &str, cwe: Option<&str>, title: &str) -> ClassifiedFinding {
    if let Some(class) = exact_class(class_label) {
        return ClassifiedFinding {
            class,
            inferred: false,
        };
    }
    let inferred = cwe
        .and_then(class_from_cwe)
        .or_else(|| class_from_keywords(&format!("{class_label} {title}")))
        .unwrap_or(FindingClass::Other);
    ClassifiedFinding {
        class: inferred,
        inferred: true,
    }
}

fn exact_class(label: &str) -> Option<FindingClass> {
    match label.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "mem-oob-write" => Some(FindingClass::MemOobWrite),
        "mem-oob-read" => Some(FindingClass::MemOobRead),
        "mem-use-after-free" | "mem-uaf" => Some(FindingClass::MemUseAfterFree),
        "mem-double-free" => Some(FindingClass::MemDoubleFree),
        "mem-uninit" => Some(FindingClass::MemUninit),
        "int-overflow" => Some(FindingClass::IntOverflow),
        "injection" => Some(FindingClass::Injection),
        "path-traversal" => Some(FindingClass::PathTraversal),
        "ssrf" => Some(FindingClass::Ssrf),
        "xxe" => Some(FindingClass::Xxe),
        "deserialization" => Some(FindingClass::Deserialization),
        "auth-bypass" => Some(FindingClass::AuthBypass),
        "authz-missing" => Some(FindingClass::AuthzMissing),
        "crypto-misuse" => Some(FindingClass::CryptoMisuse),
        "secret-exposure" => Some(FindingClass::SecretExposure),
        "race-condition" => Some(FindingClass::RaceCondition),
        "dos" => Some(FindingClass::Dos),
        "info-leak" => Some(FindingClass::InfoLeak),
        "logic-error" => Some(FindingClass::LogicError),
        "other" => Some(FindingClass::Other),
        _ => None,
    }
}

fn class_from_cwe(cwe: &str) -> Option<FindingClass> {
    let number: u32 = cwe
        .trim()
        .trim_start_matches("CWE-")
        .trim_start_matches("cwe-")
        .parse()
        .ok()?;
    class_from_cwe_number(number)
}

fn class_from_cwe_number(number: u32) -> Option<FindingClass> {
    Some(match number {
        787 | 121 | 122 | 124 | 823 => FindingClass::MemOobWrite,
        125 | 126 | 127 => FindingClass::MemOobRead,
        119 | 120 | 131 => FindingClass::MemOobWrite,
        416 => FindingClass::MemUseAfterFree,
        415 => FindingClass::MemDoubleFree,
        457 | 908 | 909 => FindingClass::MemUninit,
        190 | 191 | 680 => FindingClass::IntOverflow,
        77 | 78 | 79 | 89 | 94 | 917 => FindingClass::Injection,
        22 | 23 | 36 => FindingClass::PathTraversal,
        918 => FindingClass::Ssrf,
        611 => FindingClass::Xxe,
        502 => FindingClass::Deserialization,
        287 | 288 | 290 | 306 => FindingClass::AuthBypass,
        285 | 639 | 862 | 863 => FindingClass::AuthzMissing,
        326 | 327 | 328 | 330 | 338 => FindingClass::CryptoMisuse,
        798 | 312 | 522 => FindingClass::SecretExposure,
        362 | 367 => FindingClass::RaceCondition,
        400 | 770 | 835 => FindingClass::Dos,
        200 | 209 | 532 => FindingClass::InfoLeak,
        840 | 841 => FindingClass::LogicError,
        _ => return None,
    })
}

fn class_from_keywords(text: &str) -> Option<FindingClass> {
    let text = text.to_ascii_lowercase();
    let table: &[(&[&str], FindingClass)] = &[
        (&["oob write", "out-of-bounds write", "heap overflow", "stack overflow", "buffer overflow"], FindingClass::MemOobWrite),
        (&["oob read", "out-of-bounds read", "overread"], FindingClass::MemOobRead),
        (&["use-after-free", "use after free", "uaf"], FindingClass::MemUseAfterFree),
        (&["double free", "double-free"], FindingClass::MemDoubleFree),
        (&["uninitialized"], FindingClass::MemUninit),
        (&["integer overflow", "integer truncation", "int overflow"], FindingClass::IntOverflow),
        (&["sql injection", "command injection", "xss", "code injection", "template injection"], FindingClass::Injection),
        (&["path traversal", "directory traversal", "zip slip"], FindingClass::PathTraversal),
        (&["ssrf", "server-side request forgery"], FindingClass::Ssrf),
        (&["xxe", "xml external entity"], FindingClass::Xxe),
        (&["deserialization", "unsafe pickle", "unsafe yaml"], FindingClass::Deserialization),
        (&["auth bypass", "authentication bypass", "missing authentication"], FindingClass::AuthBypass),
        (&["authorization", "idor", "missing authz", "privilege escalation"], FindingClass::AuthzMissing),
        (&["weak cipher", "weak hash", "hardcoded iv", "insecure random", "crypto"], FindingClass::CryptoMisuse),
        (&["hardcoded secret", "hardcoded credential", "hardcoded password", "api key"], FindingClass::SecretExposure),
        (&["race condition", "toctou"], FindingClass::RaceCondition),
        (&["denial of service", "infinite loop", "resource exhaustion"], FindingClass::Dos),
        (&["information leak", "info leak", "information disclosure"], FindingClass::InfoLeak),
    ];
    table
        .iter()
        .find(|(needles, _)| needles.iter().any(|needle| text.contains(needle)))
        .map(|(_, class)| *class)
}

/// Span-extended clustering: rows in the same file whose lines sit within
/// `CLUSTER_WINDOW_LINES` of any row already in the cluster merge into one
/// cluster. The window extends with the span, so a chain of nearby rows
/// stays one cluster. Identity/title strings are deliberately not inputs.
pub const CLUSTER_WINDOW_LINES: u32 = 15;

/// Assign cluster ids to `(file, line)` rows. Returns one cluster id per
/// input row, aligned by index. Ids are `file:first-line` of each cluster —
/// stable under row order.
pub fn assign_clusters(rows: &[(String, u32)]) -> Vec<String> {
    let mut order: Vec<usize> = (0..rows.len()).collect();
    order.sort_by(|a, b| rows[*a].cmp(&rows[*b]));
    let mut ids = vec![String::new(); rows.len()];
    let mut current: Option<(String, u32, String)> = None; // (file, span_end, cluster_id)
    for index in order {
        let (file, line) = &rows[index];
        current = Some(next_cluster(current, file, *line));
        let (_, _, cluster_id) = current.as_ref().expect("just set");
        ids[index] = cluster_id.clone();
    }
    ids
}

fn next_cluster(
    current: Option<(String, u32, String)>,
    file: &str,
    line: u32,
) -> (String, u32, String) {
    if let Some((cluster_file, span_end, cluster_id)) = current {
        if cluster_file == file && line <= span_end.saturating_add(CLUSTER_WINDOW_LINES) {
            return (cluster_file, span_end.max(line), cluster_id);
        }
    }
    (file.to_string(), line, format!("{file}:{line}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preauth_claims_stand_but_local_critical_claims_are_capped() {
        let preauth = enforce_severity_ceiling(
            Severity::Critical,
            Precondition::parse("unauth-network"),
        );
        assert_eq!(preauth.severity, Severity::Critical);
        assert!(!preauth.tier_capped);

        let local = enforce_severity_ceiling(Severity::Critical, Precondition::parse("local_uid"));
        assert_eq!(local.severity, Severity::High);
        assert!(local.tier_capped);

        let physical =
            enforce_severity_ceiling(Severity::High, Precondition::parse("physical"));
        assert_eq!(physical.severity, Severity::Medium);
        assert!(physical.tier_capped);
    }

    #[test]
    fn unknown_precondition_leaves_the_claim_untouched() {
        let result = enforce_severity_ceiling(Severity::Critical, Precondition::parse("wizard"));
        assert_eq!(result.severity, Severity::Critical);
        assert!(!result.tier_capped);
    }

    #[test]
    fn exact_class_labels_are_not_flagged_but_inference_is() {
        let exact = classify("mem-oob-write", None, "whatever");
        assert_eq!(exact.class, FindingClass::MemOobWrite);
        assert!(!exact.inferred);

        let via_cwe = classify("weird-label", Some("CWE-416"), "");
        assert_eq!(via_cwe.class, FindingClass::MemUseAfterFree);
        assert!(via_cwe.inferred);

        let via_title = classify("", None, "Heap overflow in decoder");
        assert_eq!(via_title.class, FindingClass::MemOobWrite);
        assert!(via_title.inferred);

        let unknown = classify("", None, "something odd");
        assert_eq!(unknown.class, FindingClass::Other);
        assert!(unknown.inferred);
    }

    #[test]
    fn clusters_span_extend_within_the_window_and_split_across_files() {
        let rows = vec![
            ("a.c".to_string(), 100),
            ("a.c".to_string(), 112), // within 15 of 100
            ("a.c".to_string(), 125), // within 15 of 112 (span extended)
            ("a.c".to_string(), 200), // new cluster
            ("b.c".to_string(), 100), // different file
        ];

        let ids = assign_clusters(&rows);

        assert_eq!(ids[0], ids[1]);
        assert_eq!(ids[1], ids[2]);
        assert_ne!(ids[2], ids[3]);
        assert_ne!(ids[0], ids[4]);
        assert_eq!(ids[0], "a.c:100");
    }

    #[test]
    fn cluster_ids_are_stable_under_input_order() {
        let forward = vec![("a.c".to_string(), 100), ("a.c".to_string(), 110)];
        let reversed = vec![("a.c".to_string(), 110), ("a.c".to_string(), 100)];

        assert_eq!(assign_clusters(&forward)[0], assign_clusters(&reversed)[1]);
    }
}
