use serde::{Deserialize, Serialize};

use super::Finding;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingIdentityMatchTier {
    StableFingerprint,
    DedupCollision,
    /// Identity reused from an open row in an earlier run that shares the
    /// finding's dedup_key and file. Rows are never merged across runs —
    /// only the durable identity converges.
    DedupKeyCrossRun,
}

impl FindingIdentityMatchTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StableFingerprint => "stable_fp",
            Self::DedupCollision => "dedup_collision",
            Self::DedupKeyCrossRun => "dedup_key_cross_run",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FindingIdentityKey {
    pub key: String,
    pub match_tier: FindingIdentityMatchTier,
}

pub(crate) struct FindingIdentityInput<'a> {
    pub tool: &'a str,
    pub rule_id: &'a str,
    pub file_path: &'a str,
}

pub(crate) fn finding_identity_key_for_finding(finding: &Finding) -> FindingIdentityKey {
    finding_identity_key_for_input(FindingIdentityInput {
        tool: &finding.tool,
        rule_id: &finding.rule_id,
        file_path: &finding.file_path,
    })
}

pub(crate) fn finding_identity_key_for_input(
    input: FindingIdentityInput<'_>,
) -> FindingIdentityKey {
    FindingIdentityKey {
        key: stable_identity_key(&input),
        match_tier: FindingIdentityMatchTier::StableFingerprint,
    }
}

pub fn compute_finding_identity_id(target_id: &str, identity_key: &str) -> String {
    let hash = crate::identity::hash_parts(
        "finding-identity",
        &[target_id.trim().as_bytes(), identity_key.trim().as_bytes()],
    );
    format!("fi_{}", hash.as_str())
}

/// Durable identity is intentionally independent of producer-supplied prose,
/// evidence, and display locations. Evidence is verified at the persistence
/// boundary, while line numbers are mutable presentation metadata; neither can
/// safely decide review/proof continuity.
///
/// The legacy `Finding` shape does not carry the richer symbol/AST/blob-span
/// context used by native v3 observations, so use the same documented generic
/// fallback as `stable_fingerprint_for_tool`: tool family, rule id, and
/// normalized file path. Existing exact-fingerprint/dedup identities are
/// considered before this fallback, so stored identities are not rewritten.
fn stable_identity_key(input: &FindingIdentityInput<'_>) -> String {
    crate::identity::stable_fingerprint_for_tool(
        input.tool,
        input.rule_id,
        input.file_path,
        "",
        "",
    )
}

pub fn finding_identity_alias(identity_id: &str) -> String {
    let suffix = identity_id
        .trim_start_matches("fi_")
        .chars()
        .take(8)
        .collect::<String>()
        .to_ascii_uppercase();
    format!("FI-{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::FindingEvidence;

    fn finding(message: &str, line: u32) -> Finding {
        Finding {
            fingerprint: format!("fp3_{}", message.replace(' ', "-")),
            rule_id: "CWE-89".to_string(),
            title: message.to_string(),
            file_path: "src/db.rs".to_string(),
            start_line: line,
            message: message.to_string(),
            tool: "semgrep".to_string(),
            ..Finding::default()
        }
    }

    #[test]
    fn finding_identity_id_is_target_scoped_and_stable() {
        let one = compute_finding_identity_id("/repo/a", "fp3_abc123");
        let two = compute_finding_identity_id("/repo/a", "fp3_abc123");
        let other_target = compute_finding_identity_id("/repo/b", "fp3_abc123");

        assert_eq!(one, two);
        assert_ne!(one, other_target);
        assert!(one.starts_with("fi_"));
        assert_eq!(finding_identity_alias(&one).len(), 11);
    }

    #[test]
    fn producer_evidence_cannot_change_identity() {
        let mut first = finding("query sink", 10);
        first.evidence = vec![FindingEvidence {
            kind: "code".to_string(),
            file_path: "src/db.rs".to_string(),
            line: 10,
            snippet: "query(first_input)".to_string(),
            rationale: "producer citation".to_string(),
            confidence: 90,
            request_blob: None,
            response_blob: None,
        }];
        let mut second = first.clone();
        second.evidence[0].snippet = "fabricated(second_input)".to_string();

        assert_eq!(
            finding_identity_key_for_finding(&first).key,
            finding_identity_key_for_finding(&second).key
        );
    }

    #[test]
    fn evidence_free_identity_ignores_title_and_message_wording() {
        let first = finding("sql injection reaches query sink", 10);
        let mut second = first.clone();
        second.fingerprint = "fp3_reworded".to_string();
        second.title = "tainted input reaches database".to_string();
        second.message = "different producer explanation".to_string();

        assert_eq!(
            finding_identity_key_for_finding(&first).key,
            finding_identity_key_for_finding(&second).key
        );
    }

    #[test]
    fn mutable_source_lines_do_not_change_durable_identity() {
        let first = finding("query sink", 10);
        let second = finding("query sink", 500);

        assert_eq!(
            finding_identity_key_for_finding(&first).key,
            finding_identity_key_for_finding(&second).key
        );
    }

    #[test]
    fn structured_rule_family_remains_part_of_identity() {
        let first = finding("query sink", 10);
        let mut second = first.clone();
        second.rule_id = "CWE-78".to_string();

        assert_ne!(
            finding_identity_key_for_finding(&first).key,
            finding_identity_key_for_finding(&second).key
        );
    }

    #[test]
    fn tool_family_remains_part_of_identity() {
        let first = finding("query sink", 10);
        let mut second = first.clone();
        second.tool = "systems-hunt".to_string();

        assert_ne!(
            finding_identity_key_for_finding(&first).key,
            finding_identity_key_for_finding(&second).key
        );
    }

    #[test]
    fn prose_only_cwe_mentions_do_not_change_identity() {
        let mut first = finding("query sink CWE-89", 10);
        first.rule_id = "db.query-sink".to_string();
        let mut second = first.clone();
        second.fingerprint = "fp3_reworded".to_string();
        second.title = "command execution CWE-78".to_string();
        second.message = "producer changed the prose classification".to_string();

        assert_eq!(
            finding_identity_key_for_finding(&first).key,
            finding_identity_key_for_finding(&second).key
        );
    }
}
