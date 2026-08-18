use serde::{Deserialize, Serialize};

use super::{extract_cwe, normalize_cwe, Finding};

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
    pub fingerprint: &'a str,
    pub rule_id: &'a str,
    pub file_path: &'a str,
    pub start_line: u32,
}

pub(crate) fn finding_identity_key_for_finding(finding: &Finding) -> FindingIdentityKey {
    finding_identity_key_for_input(FindingIdentityInput {
        fingerprint: &finding.fingerprint,
        rule_id: &finding.rule_id,
        file_path: &finding.file_path,
        start_line: finding.start_line,
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

/// Durable identity is intentionally independent of producer-supplied prose
/// and evidence. Evidence is verified at the persistence boundary, but
/// identity assignment happens before the projected row is written; allowing
/// snippets into this key would let a fabricated citation influence history
/// even when persistence later downgraded it. File, rule family, and source
/// locus are available without trusting that content.
fn stable_identity_key(input: &FindingIdentityInput<'_>) -> String {
    let weakness = weakness_key(input);
    let symbol = crate::identity::finding_identity::normalize_path(input.file_path);
    let locator = structural_locator(input);
    crate::identity::compute_stable_fp_v3(crate::identity::StableFindingInput {
        tool_family: tool_family_from_fingerprint(input.fingerprint),
        rule_id: &weakness,
        language: None,
        parser_version: None,
        normalizer_version: None,
        symbol_path_or_rename_group: Some(&symbol),
        ast_locus_hash: None,
        normalized_snippet: &locator,
        local_context_hash: None,
        disambiguator: None,
    })
}

fn structural_locator(input: &FindingIdentityInput<'_>) -> String {
    if input.start_line == 0 {
        "file".to_string()
    } else {
        format!("line:{}", input.start_line)
    }
}

/// Weakness identity may use a structured CWE embedded in the rule id, but it
/// must not infer one from a title or message whose wording can change between
/// model or human rediscoveries.
fn weakness_key(input: &FindingIdentityInput<'_>) -> String {
    extract_cwe(input.rule_id, "", "")
        .map(|cwe| format!("cwe:{}", normalize_cwe(&cwe)))
        .unwrap_or_else(|| format!("rule:{}", normalize_token(input.rule_id)))
}

fn tool_family_from_fingerprint(fingerprint: &str) -> &str {
    if fingerprint.starts_with("fp3_") {
        "kuzushi-v3"
    } else {
        "imported"
    }
}

fn normalize_token(value: &str) -> String {
    crate::identity::finding_identity::normalize_token(value)
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
    fn structural_source_lines_keep_nearby_findings_distinct() {
        let first = finding("first query sink", 10);
        let second = finding("second query sink", 11);

        assert_ne!(
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
    fn prose_only_cwe_mentions_do_not_change_weakness_identity() {
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
