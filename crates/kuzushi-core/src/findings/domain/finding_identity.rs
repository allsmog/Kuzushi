use serde::{Deserialize, Serialize};

use super::{extract_cwe, normalize_cwe, Finding, FindingEvidence};

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
    pub title: &'a str,
    pub file_path: &'a str,
    pub message: &'a str,
    pub evidence: &'a [FindingEvidence],
}

pub(crate) fn finding_identity_key_for_finding(finding: &Finding) -> FindingIdentityKey {
    finding_identity_key_for_input(FindingIdentityInput {
        fingerprint: &finding.fingerprint,
        rule_id: &finding.rule_id,
        title: &finding.title,
        file_path: &finding.file_path,
        message: &finding.message,
        evidence: &finding.evidence,
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

fn stable_identity_key(input: &FindingIdentityInput<'_>) -> String {
    let weakness = weakness_key(input);
    let symbol = crate::identity::finding_identity::normalize_path(input.file_path);
    let snippet = evidence_snippet(input.evidence).unwrap_or_else(|| text_locator(input));
    crate::identity::compute_stable_fp_v3(crate::identity::StableFindingInput {
        tool_family: tool_family_from_fingerprint(input.fingerprint),
        rule_id: &weakness,
        language: None,
        parser_version: None,
        normalizer_version: None,
        symbol_path_or_rename_group: Some(&symbol),
        ast_locus_hash: None,
        normalized_snippet: &snippet,
        local_context_hash: None,
        disambiguator: None,
    })
}

fn text_locator(input: &FindingIdentityInput<'_>) -> String {
    let parts = [input.title, input.message]
        .into_iter()
        .map(crate::identity::finding_identity::normalize_finding_text)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.is_empty() {
        "finding".to_string()
    } else {
        format!("text:{}", parts.join("\u{1f}"))
    }
}

fn weakness_key(input: &FindingIdentityInput<'_>) -> String {
    extract_cwe(input.rule_id, input.title, input.message)
        .map(|cwe| format!("cwe:{}", normalize_cwe(&cwe)))
        .unwrap_or_else(|| format!("rule:{}", normalize_token(input.rule_id)))
}

fn evidence_snippet(evidence: &[FindingEvidence]) -> Option<String> {
    let mut snippets = evidence
        .iter()
        .filter_map(|evidence| {
            let snippet =
                crate::identity::finding_identity::normalize_finding_text(&evidence.snippet);
            (!snippet.is_empty()).then_some(snippet)
        })
        .collect::<Vec<_>>();
    if snippets.is_empty() {
        return None;
    }
    snippets.sort();
    Some(snippets.join("\u{1f}"))
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
    fn evidence_identity_ignores_line_number() {
        let first = Finding {
            fingerprint: "fp3-first".to_string(),
            rule_id: "CWE-79".to_string(),
            title: "xss".to_string(),
            file_path: "src/app.ts".to_string(),
            message: "html sink".to_string(),
            evidence: vec![FindingEvidence {
                kind: "code".to_string(),
                file_path: "src/app.ts".to_string(),
                line: 10,
                snippet: "render(user.name)".to_string(),
                rationale: "sink".to_string(),
                confidence: 90,
                request_blob: None,
                response_blob: None,
            }],
            ..Finding::default()
        };
        let mut second = first.clone();
        second.fingerprint = "fp3-second".to_string();
        second.evidence[0].line = 42;

        let first_key = finding_identity_key_for_finding(&first);
        let second_key = finding_identity_key_for_finding(&second);

        assert_eq!(first_key.key, second_key.key);
        assert_eq!(
            first_key.match_tier,
            FindingIdentityMatchTier::StableFingerprint
        );
    }

    #[test]
    fn empty_evidence_identity_ignores_line_number() {
        let first = Finding {
            fingerprint: "fp3-first".to_string(),
            rule_id: "CWE-89".to_string(),
            title: "sql injection".to_string(),
            file_path: "src/db.rs".to_string(),
            start_line: 10,
            message: "query sink".to_string(),
            evidence: Vec::new(),
            ..Finding::default()
        };
        let mut second = first.clone();
        second.fingerprint = "fp3-second".to_string();
        second.start_line = 500;

        let first_key = finding_identity_key_for_finding(&first);
        let second_key = finding_identity_key_for_finding(&second);

        assert_eq!(first_key.key, second_key.key);
    }

    #[test]
    fn empty_evidence_identity_uses_text_locator() {
        let first = Finding {
            fingerprint: "fp3-first".to_string(),
            rule_id: "CWE-89".to_string(),
            title: "sql injection".to_string(),
            file_path: "src/db.rs".to_string(),
            start_line: 10,
            message: "query sink".to_string(),
            evidence: Vec::new(),
            ..Finding::default()
        };
        let mut second = first.clone();
        second.message = "command sink".to_string();

        let first_key = finding_identity_key_for_finding(&first);
        let second_key = finding_identity_key_for_finding(&second);

        assert_ne!(first_key.key, second_key.key);
    }
}
