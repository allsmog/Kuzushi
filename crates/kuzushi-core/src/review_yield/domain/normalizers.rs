use std::path::Path;

use crate::findings::{normalize_cwe, GroundingStatus, Severity, StaticProofState, VulnSource};
use crate::workspace::inventory::language_for_path;

/// Discovery channels, verbatim from `$.vuln_source`. Never derived from the
/// tool name: `VulnSource::from_tool` has a silent catch-all.
pub const VULN_SOURCES: &[&str] = &[
    "sarif",
    "analysis",
    "analysis-multi",
    "diff-analyzer",
    "infer",
    "fuzzing",
    "unknown",
];

/// Tool families. A tool outside the table is `other` — the raw tool id is
/// never exported.
pub const TOOL_FAMILIES: &[&str] = &[
    "semgrep",
    "codeql",
    "secret-scan",
    "iac-scan",
    "dep-hygiene",
    "govulncheck",
    "infer",
    "systems-hunt",
    "carlini-threat-hunt",
    "full-mode-multi",
    "variant-ndiff",
    "chains",
    "other",
];

pub const EVIDENCE_KINDS: &[&str] = &["source", "sink", "sanitizer", "call_path", "http", "other"];

pub const IDENTITY_MATCH_TIERS: &[&str] = &[
    "stable_fp",
    "dedup_collision",
    "dedup_key_cross_run",
    "model_dedupe",
    "unknown",
];

pub const GROUNDING_STATUSES: &[&str] = &[
    "grounded",
    "line_drift",
    "file_missing",
    "not_applicable",
    "native_or_unspecified",
];

pub const STATIC_PROOF_STATES: &[&str] = &[
    "signal_only",
    "code_cited",
    "source_sink_linked",
    "sanitizer_checked",
    "statically_confirmed",
    "statically_rejected",
    "needs_runtime_evidence",
    "missing",
];

/// Substring rules for evidence kinds, first match wins. `path` and `trace`
/// follow `call` so a "call-path" kind lands on one token.
const EVIDENCE_KIND_RULES: &[(&str, &str)] = &[
    ("source", "source"),
    ("sink", "sink"),
    ("sanit", "sanitizer"),
    ("call", "call_path"),
    ("path", "call_path"),
    ("trace", "call_path"),
    ("http", "http"),
];

/// Critical is 0 so that a lower rank always means a more severe finding.
pub fn severity_rank(severity: Severity) -> u8 {
    5 - (severity as u8)
}

pub fn vuln_source_token(source: Option<VulnSource>) -> &'static str {
    match source {
        Some(VulnSource::Sarif) => "sarif",
        Some(VulnSource::Ainalysis) => "analysis",
        Some(VulnSource::AinalysisMulti) => "analysis-multi",
        Some(VulnSource::DiffAnalyzer) => "diff-analyzer",
        Some(VulnSource::Infer) => "infer",
        Some(VulnSource::Fuzzing) => "fuzzing",
        None => "unknown",
    }
}

pub fn static_proof_token(state: Option<StaticProofState>) -> &'static str {
    state.map(StaticProofState::as_str).unwrap_or("missing")
}

/// Native scans leave `$.grounding` unset; that is a distinct state from an
/// import whose citation could not be checked (`not_applicable`).
pub fn grounding_token(grounding: Option<&GroundingStatus>) -> &'static str {
    grounding
        .map(GroundingStatus::label)
        .unwrap_or("native_or_unspecified")
}

pub fn tool_family(tool: &str) -> &'static str {
    let lower = tool.trim().to_ascii_lowercase();
    TOOL_FAMILIES
        .iter()
        .find(|family| **family == lower)
        .copied()
        .unwrap_or("other")
}

pub fn normalize_evidence_kind(kind: &str) -> &'static str {
    let lower = kind.trim().to_ascii_lowercase();
    EVIDENCE_KIND_RULES
        .iter()
        .find(|(needle, _)| lower.contains(needle))
        .map(|(_, token)| *token)
        .unwrap_or("other")
}

/// `$.identityMatchTier` is written through `FindingIdentityMatchTier::as_str`,
/// but `finding_identity_fingerprints.match_basis` also carries the DB-only
/// `model_dedupe` basis. Anything else is `unknown` rather than a guessed tier.
pub fn identity_match_tier(raw: Option<&str>) -> &'static str {
    let tier = raw.map(str::trim).unwrap_or_default();
    IDENTITY_MATCH_TIERS
        .iter()
        .find(|known| **known == tier && **known != "unknown")
        .copied()
        .unwrap_or("unknown")
}

pub fn language_family(path: &str) -> String {
    language_for_path(Path::new(path))
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn is_attack_chain(tool: &str, rule_id: &str) -> bool {
    tool.trim().eq_ignore_ascii_case("chains")
        || rule_id
            .trim()
            .to_ascii_lowercase()
            .starts_with("exploit-chain/")
}

/// Bounded rule families keyed off the producer's category, then the rule id.
/// Only the table's own tokens are ever emitted, so no raw rule id escapes.
pub fn rule_family(category: Option<&str>, rule_id: &str) -> String {
    cwe_family(category)
        .or_else(|| cwe_family(Some(rule_id)))
        .or_else(|| keyword_family(category))
        .or_else(|| keyword_family(Some(rule_id)))
        .unwrap_or_else(|| "other".to_string())
}

fn cwe_family(value: Option<&str>) -> Option<String> {
    let lower = value?.trim().to_ascii_lowercase();
    let digits = lower.contains("cwe").then(|| normalize_cwe(&lower))?;
    (!digits.is_empty()).then(|| format!("cwe-{digits}"))
}

fn keyword_family(value: Option<&str>) -> Option<String> {
    let lower = value?.trim().to_ascii_lowercase();
    RULE_FAMILY_KEYWORDS
        .iter()
        .find(|(needle, _)| lower.contains(needle))
        .map(|(_, family)| (*family).to_string())
}

/// Keyword rules, first match wins. Order is load-bearing: `sql` precedes the
/// generic `inject`, and `command` precedes it too.
const RULE_FAMILY_KEYWORDS: &[(&str, &str)] = &[
    ("sql", "sql_injection"),
    ("command", "command_injection"),
    ("xss", "xss"),
    ("cross-site-script", "xss"),
    ("inject", "injection"),
    ("traversal", "path_traversal"),
    ("deserial", "deserialization"),
    ("ssrf", "ssrf"),
    ("csrf", "csrf"),
    ("authz", "authorization"),
    ("authoriz", "authorization"),
    ("authent", "authentication"),
    ("crypto", "crypto"),
    ("secret", "secrets"),
    ("credential", "secrets"),
    ("hardcoded", "secrets"),
    ("overflow", "memory_safety"),
    ("use-after-free", "memory_safety"),
    ("double-free", "memory_safety"),
    ("race", "concurrency"),
    ("redos", "availability"),
    ("denial-of-service", "availability"),
];

/// Every rule-family token this normalizer can emit, plus the `cwe-<n>` shape
/// documented in the schema.
pub fn rule_family_keyword_tokens() -> Vec<&'static str> {
    let mut tokens: Vec<&'static str> = RULE_FAMILY_KEYWORDS
        .iter()
        .map(|(_, family)| *family)
        .collect();
    tokens.push("other");
    tokens.sort_unstable();
    tokens.dedup();
    tokens
}
