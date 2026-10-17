use serde::{Deserialize, Serialize};
use std::path::Path;

use super::{extract_cwe, normalize_cwe, Finding};

/// Evidence basis used to decide whether a durable identity is safe to fold
/// or propagate across observations. This is intentionally separate from the
/// legacy match tier: `stable_fp` covered both source-backed and file-only
/// structural identities and therefore cannot authorize an identity-wide
/// decision by itself.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FindingIdentityBasis {
    ExactProducerFingerprint,
    CrossRunDedupKey,
    SourceLocator,
    FileFallback,
}

impl FindingIdentityBasis {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExactProducerFingerprint => "exact_producer_fingerprint",
            Self::CrossRunDedupKey => "cross_run_dedup_key",
            Self::SourceLocator => "source_locator",
            Self::FileFallback => "file_fallback",
        }
    }

    pub fn is_strong(self) -> bool {
        !matches!(self, Self::FileFallback)
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Option<Self> {
        Some(match value.trim() {
            "exact_producer_fingerprint" => Self::ExactProducerFingerprint,
            "cross_run_dedup_key" => Self::CrossRunDedupKey,
            "source_locator" => Self::SourceLocator,
            "file_fallback" => Self::FileFallback,
            _ => return None,
        })
    }

    fn from_legacy_match_tier(raw: Option<&str>) -> Self {
        match raw {
            Some("dedup_key_cross_run") => Self::CrossRunDedupKey,
            _ => Self::FileFallback,
        }
    }
}

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
    pub basis: FindingIdentityBasis,
}

pub(crate) struct FindingIdentityInput<'a> {
    pub rule_id: &'a str,
    pub file_path: &'a str,
    pub symbol_locator: Option<&'a str>,
    pub source_hint: Option<&'a str>,
}

#[cfg(test)]
pub(crate) fn finding_identity_key_for_finding(finding: &Finding) -> FindingIdentityKey {
    finding_identity_key_for_input(FindingIdentityInput {
        rule_id: &finding.rule_id,
        file_path: &finding.file_path,
        symbol_locator: finding.defensible_source_locator().as_deref(),
        source_hint: None,
    })
}

pub(crate) fn finding_identity_key_for_finding_at_target(
    finding: &Finding,
    target_root: &Path,
) -> FindingIdentityKey {
    let source_hint = host_source_hint(target_root, finding);
    let symbol_locator = finding.defensible_source_locator();
    finding_identity_key_for_input(FindingIdentityInput {
        rule_id: &finding.rule_id,
        file_path: &finding.file_path,
        symbol_locator: symbol_locator.as_deref(),
        source_hint: source_hint.as_deref(),
    })
}

pub(crate) fn finding_identity_key_for_captured_source(
    finding: &Finding,
    source: &str,
) -> FindingIdentityKey {
    let source_hint = finding
        .start_line
        .checked_sub(1)
        .and_then(|line| source.lines().nth(line as usize))
        .map(crate::identity::finding_identity::normalize_finding_text)
        .filter(|line| !line.is_empty());
    finding_identity_key_for_input(FindingIdentityInput {
        rule_id: &finding.rule_id,
        file_path: &finding.file_path,
        symbol_locator: finding.defensible_source_locator().as_deref(),
        source_hint: source_hint.as_deref(),
    })
}

pub(crate) fn finding_identity_key_for_input(
    input: FindingIdentityInput<'_>,
) -> FindingIdentityKey {
    let basis = if input.symbol_locator.is_some() {
        FindingIdentityBasis::SourceLocator
    } else {
        FindingIdentityBasis::FileFallback
    };
    FindingIdentityKey {
        key: stable_identity_key(&input),
        match_tier: FindingIdentityMatchTier::StableFingerprint,
        basis,
    }
}

impl Finding {
    /// Returns an explicit persisted basis when available. Legacy findings
    /// are derived conservatively: only the old cross-run tier proves its
    /// basis; the broad `stable_fp` tier becomes file fallback.
    pub fn effective_identity_basis(&self) -> FindingIdentityBasis {
        self.identity_basis.unwrap_or_else(|| {
            FindingIdentityBasis::from_legacy_match_tier(self.identity_match_tier.as_deref())
        })
    }
}

pub fn compute_finding_identity_id(target_id: &str, identity_key: &str) -> String {
    let hash = crate::identity::hash_parts(
        "finding-identity",
        &[target_id.trim().as_bytes(), identity_key.trim().as_bytes()],
    );
    format!("fi_{}", hash.as_str())
}

/// Immutable ledger key carried by a loaded finding. Legacy findings use
/// their fingerprint; observation readers must not resolve a newer row first.
pub fn finding_observation_identity(finding: &Finding) -> &str {
    finding
        .identity_id
        .as_deref()
        .unwrap_or(&finding.fingerprint)
}

/// Durable identity is intentionally independent of producer-supplied prose,
/// evidence, and display locations. Evidence is verified at the persistence
/// boundary, while line numbers are mutable presentation metadata; neither can
/// safely decide review/proof continuity.
///
/// When the cited target source is available, the host reads the cited line and
/// uses its normalized content as a line-number-independent identity hint.
/// Different statements usually mint different keys, but identical statements
/// remain ambiguous and the resulting basis stays
/// [`FindingIdentityBasis::FileFallback`]. If source is unavailable, the
/// fallback is the structured weakness and normalized file path.
/// Existing exact-fingerprint/dedup identities are considered before this
/// fallback, so stored identities are not rewritten.
fn stable_identity_key(input: &FindingIdentityInput<'_>) -> String {
    let weakness = weakness_key(input.rule_id);
    let file_path = crate::identity::finding_identity::normalize_path(input.file_path);
    let identity_scope = input
        .symbol_locator
        .map(|symbol| format!("{file_path}#{symbol}"))
        .unwrap_or(file_path);
    crate::identity::compute_stable_fp_v3(crate::identity::StableFindingInput {
        tool_family: "kuzushi",
        rule_id: &weakness,
        language: None,
        parser_version: None,
        normalizer_version: None,
        symbol_path_or_rename_group: Some(&identity_scope),
        ast_locus_hash: None,
        normalized_snippet: input.source_hint.unwrap_or("file"),
        local_context_hash: None,
        disambiguator: None,
    })
}

fn weakness_key(rule_id: &str) -> String {
    extract_cwe(rule_id, "", "")
        .map(|cwe| format!("cwe:{}", normalize_cwe(&cwe)))
        .unwrap_or_else(|| {
            format!(
                "rule:{}",
                crate::identity::finding_identity::normalize_token(rule_id)
            )
        })
}

fn host_source_hint(target_root: &Path, finding: &Finding) -> Option<String> {
    if finding.start_line == 0 {
        return None;
    }
    let path = super::safe_target_path(target_root, &finding.file_path)?;
    let source =
        crate::bounded_file::read_utf8_text_within(target_root, &path, 8 * 1024 * 1024).ok()?;
    source
        .lines()
        .nth(finding.start_line.saturating_sub(1) as usize)
        .map(crate::identity::finding_identity::normalize_finding_text)
        .filter(|line| !line.is_empty())
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
    fn tool_family_does_not_split_cross_tool_corroboration() {
        let first = finding("query sink", 10);
        let mut second = first.clone();
        second.tool = "systems-hunt".to_string();

        assert_eq!(
            finding_identity_key_for_finding(&first).key,
            finding_identity_key_for_finding(&second).key
        );
    }

    #[test]
    fn host_source_hint_distinguishes_different_statements_but_stays_weak() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("src")).unwrap();
        std::fs::write(
            temp.path().join("src/db.rs"),
            "query(first_input);\nquery(second_input);\n",
        )
        .unwrap();
        let first = finding("query sink", 1);
        let second = finding("query sink", 2);

        assert_ne!(
            finding_identity_key_for_finding_at_target(&first, temp.path()).key,
            finding_identity_key_for_finding_at_target(&second, temp.path()).key
        );
        assert_eq!(
            finding_identity_key_for_finding_at_target(&first, temp.path()).basis,
            FindingIdentityBasis::FileFallback
        );
    }

    #[test]
    fn host_source_content_survives_line_drift() {
        let first_target = tempfile::tempdir().unwrap();
        let second_target = tempfile::tempdir().unwrap();
        for target in [&first_target, &second_target] {
            std::fs::create_dir_all(target.path().join("src")).unwrap();
        }
        std::fs::write(first_target.path().join("src/db.rs"), "query(input);\n").unwrap();
        std::fs::write(
            second_target.path().join("src/db.rs"),
            "use crate::db;\nquery(input);\n",
        )
        .unwrap();
        let first = finding("query sink", 1);
        let second = finding("query sink", 2);

        assert_eq!(
            finding_identity_key_for_finding_at_target(&first, first_target.path()).key,
            finding_identity_key_for_finding_at_target(&second, second_target.path()).key
        );
    }

    #[test]
    fn only_a_qualified_persistable_symbol_mints_source_locator_basis() {
        let mut qualified = finding("query sink", 10);
        qualified.symbol_locator = Some("crate::db::execute".to_string());
        let mut other = qualified.clone();
        other.symbol_locator = Some("crate::db::prepare".to_string());
        let mut unqualified = qualified.clone();
        unqualified.symbol_locator = Some("execute".to_string());

        let qualified_key = finding_identity_key_for_finding(&qualified);
        assert_eq!(qualified_key.basis, FindingIdentityBasis::SourceLocator);
        assert_ne!(
            qualified_key.key,
            finding_identity_key_for_finding(&other).key
        );
        assert_eq!(
            finding_identity_key_for_finding(&unqualified).basis,
            FindingIdentityBasis::FileFallback
        );
    }

    #[test]
    fn placeholder_symbol_never_upgrades_file_fallback_identity() {
        let mut finding = finding("query sink", 10);
        finding.symbol_locator = Some("<unknown>".to_string());

        assert_eq!(
            finding_identity_key_for_finding(&finding).basis,
            FindingIdentityBasis::FileFallback
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

    #[test]
    fn ambiguous_legacy_stable_tier_derives_as_file_fallback() {
        let mut legacy = finding("query sink", 10);
        legacy.identity_match_tier = Some("stable_fp".to_string());
        assert_eq!(
            legacy.effective_identity_basis(),
            FindingIdentityBasis::FileFallback
        );

        legacy.identity_match_tier = Some("dedup_key_cross_run".to_string());
        assert_eq!(
            legacy.effective_identity_basis(),
            FindingIdentityBasis::CrossRunDedupKey
        );
    }
}
