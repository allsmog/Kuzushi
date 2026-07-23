use super::*;
use std::path::Path;

impl VulnSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sarif => "sarif",
            Self::Ainalysis => "analysis",
            Self::AinalysisMulti => "analysis-multi",
            Self::DiffAnalyzer => "diff-analyzer",
            Self::Infer => "infer",
            Self::Fuzzing => "fuzzing",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "sarif" => Some(Self::Sarif),
            "analysis" | "ainalysis" => Some(Self::Ainalysis),
            "analysis-multi" | "analysis_multi" | "ainalysis-multi" | "ainalysis_multi" => {
                Some(Self::AinalysisMulti)
            }
            "diff-analyzer" | "diff_analyzer" => Some(Self::DiffAnalyzer),
            "infer" => Some(Self::Infer),
            "fuzzing" => Some(Self::Fuzzing),
            _ => None,
        }
    }

    /// Heuristic mapping from existing tool ids to a default channel.
    /// Used so existing modules don't have to be retrofitted in this
    /// phase — they keep emitting `tool="systems-hunt"` and we infer
    /// the source.
    pub fn from_tool(tool: &str) -> Self {
        match tool {
            "semgrep" | "codeql" | "secret-scan" | "iac-scan" | "dep-hygiene" | "govulncheck" => {
                Self::Sarif
            }
            "systems-hunt" | "carlini-threat-hunt" => Self::Ainalysis,
            "full-mode-multi" => Self::AinalysisMulti,
            "variant-ndiff" => Self::DiffAnalyzer,
            "infer" => Self::Infer,
            _ => Self::Ainalysis,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FindingEvidence {
    pub kind: String,
    pub file_path: String,
    pub line: u32,
    pub snippet: String,
    pub rationale: String,
    pub confidence: u8,
    /// Raw HTTP request blob when `kind == "http-request"` — populated by
    /// the Burp / HAR import adapters (M2 §2.3). `None` for code-location
    /// evidence kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_blob: Option<String>,
    /// Raw HTTP response blob when `kind == "http-request"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_blob: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FindingSource {
    pub tool: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vuln_source: Option<VulnSource>,
    pub source_signature: String,
    pub first_scan_id: String,
    pub last_scan_id: String,
    pub first_seen_at: String,
    pub last_seen_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    pub id: Option<i64>,
    pub scan_id: Option<String>,
    #[serde(
        default,
        rename = "identityId",
        alias = "identity_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_id: Option<String>,
    #[serde(
        default,
        rename = "identityMatchTier",
        alias = "identity_match_tier",
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_match_tier: Option<String>,
    pub fingerprint: String,
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub file_path: String,
    pub start_line: u32,
    pub end_line: Option<u32>,
    pub message: String,
    pub tool: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_fingerprint: Option<String>,
    #[serde(
        rename = "staticProofState",
        alias = "static_proof_state",
        skip_serializing_if = "Option::is_none"
    )]
    pub static_proof_state: Option<StaticProofState>,
    pub triage: Option<TriageOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub triaged_by: Option<TriageAuthor>,
    /// Most-recent empirical verification, when present. Loaded by
    /// `FindingStore::get_finding_by_*` from the v3 verification
    /// projection; in-memory `Finding`s built via `Finding::new_tool`
    /// leave this `None` until persisted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<PersistedVerification>,
    pub created_at: String,
    /// Discovery channel — populated automatically from `tool` if not
    /// set explicitly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vuln_source: Option<VulnSource>,
    /// Cross-channel collision key. Two findings with the same
    /// `dedup_key` in the same scan are treated as the same underlying
    /// vulnerability: the higher-severity one wins and the tool list
    /// merges. Computed from `(file, line/8, normalized_cwe)` so nearby
    /// scanner and agent signals still converge without collapsing broad
    /// 16-line regions in dense security-sensitive files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dedup_key: Option<String>,
    /// Exact-line source signature retained alongside the bucketed
    /// dedup key. This preserves cannon-style provenance without making
    /// exact lines the canonical merge identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_signature: Option<String>,
    #[serde(default)]
    pub corroboration_count: u32,
    #[serde(default, skip_serializing_if = "is_false")]
    pub suppressed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snoozed_until: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// Producer-supplied plain-language statement of attacker gain and who
    /// is affected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impact: Option<String>,
    /// Producer-supplied category label (freeform; the closed class enum is
    /// derived separately at ingest).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Producer-supplied concrete exploitation walkthrough.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exploit_scenario: Option<String>,
    /// Attacker preconditions. Entries matching the closed `Precondition`
    /// vocabulary drive the mechanical severity ceiling.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preconditions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<FindingEvidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<FindingSource>,
    /// Import-grounding verdict stamped when the finding entered from an
    /// external source (`workspace:import-findings`, `fuzz:import`).
    /// `None` for findings born from native scans/hunts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grounding: Option<super::GroundingStatus>,
}

impl Default for Finding {
    fn default() -> Self {
        Self {
            id: None,
            scan_id: None,
            identity_id: None,
            identity_match_tier: None,
            fingerprint: String::new(),
            rule_id: String::new(),
            title: String::new(),
            severity: Severity::Unknown,
            file_path: String::new(),
            start_line: 0,
            end_line: None,
            message: String::new(),
            tool: String::new(),
            actor_fingerprint: None,
            static_proof_state: None,
            triage: None,
            triaged_by: None,
            verification: None,
            created_at: String::new(),
            vuln_source: None,
            dedup_key: None,
            source_signature: None,
            corroboration_count: 0,
            suppressed: false,
            snoozed_until: None,
            remediation: None,
            impact: None,
            category: None,
            exploit_scenario: None,
            preconditions: Vec::new(),
            references: Vec::new(),
            evidence: Vec::new(),
            sources: Vec::new(),
            grounding: None,
        }
    }
}

/// Attack-chain findings compose multiple component bugs, so their locations
/// intentionally collide with component findings. Dedupe and clustering must
/// never absorb a chain into (or collapse it with) its members.
pub fn is_attack_chain_finding(finding: &Finding) -> bool {
    finding.tool.trim().eq_ignore_ascii_case("chains")
        || finding
            .rule_id
            .trim()
            .to_ascii_lowercase()
            .starts_with("exploit-chain/")
}

pub(crate) const DEDUP_LINE_BUCKET: u32 = 8;

fn is_false(value: &bool) -> bool {
    !*value
}

pub fn compute_dedup_key(file: &str, line: u32, cwe: Option<&str>) -> String {
    let bucket = line / DEDUP_LINE_BUCKET;
    let normalised_file = file.trim_start_matches("./");
    let cwe_part = cwe.map(normalize_cwe).unwrap_or_else(|| "*".to_string());
    format!("{normalised_file}:{bucket}:{cwe_part}")
}

/// Dedup key for CWE-less findings, keyed by the closed vulnerability class
/// instead of a CWE number. The `class:` prefix cannot collide with
/// [`normalize_cwe`] output (digits only), so class keys and CWE keys never
/// cross-merge.
pub fn compute_class_dedup_key(file: &str, line: u32, class_slug: &str) -> String {
    let bucket = line / DEDUP_LINE_BUCKET;
    let normalised_file = file.trim_start_matches("./");
    format!("{normalised_file}:{bucket}:class:{class_slug}")
}

pub fn compute_source_signature(file: &str, line: u32, cwe_or_title: Option<&str>) -> String {
    let basename = Path::new(file)
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(file)
        .trim_start_matches("./");
    let identity = source_signature_identity(cwe_or_title);
    format!("{basename}:{line}:{identity}")
}

fn source_signature_identity(cwe_or_title: Option<&str>) -> String {
    let Some(value) = cwe_or_title
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return "*".to_string();
    };
    let normalized_cwe = normalize_cwe(value);
    if !normalized_cwe.is_empty() {
        return normalized_cwe;
    }
    let slug = value
        .chars()
        .filter_map(|c| {
            if c.is_ascii_alphanumeric() {
                Some(c.to_ascii_lowercase())
            } else if c.is_ascii_whitespace() || matches!(c, '-' | '_' | ':' | '/' | '.') {
                Some('-')
            } else {
                None
            }
        })
        .collect::<String>();
    let compact = slug
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    if compact.is_empty() {
        "*".to_string()
    } else {
        compact.chars().take(80).collect()
    }
}

/// Coarse root-cause key for the qualitative dedup pass.
///
/// Where [`compute_dedup_key`] merges near-identical findings (it buckets by
/// line so the same defect reported twice collapses), this drops the line
/// bucket: `(normalized_file, normalized_cwe)`. Multiple call sites of one
/// missing validation in a file share a root cause and group together, which
/// lets reporting say "12 findings across 7 root causes" instead of treating
/// every call site as an independent problem. Deliberately coarser than the
/// dedup key and used only for grouping/clustering — never to drop findings.
pub fn compute_root_cause_key(file: &str, cwe: Option<&str>) -> String {
    let normalised_file = file.trim_start_matches("./");
    let cwe_part = cwe.map(normalize_cwe).unwrap_or_else(|| "*".to_string());
    format!("{normalised_file}:{cwe_part}")
}

pub fn normalize_cwe(value: &str) -> String {
    let lower = value.trim().to_ascii_lowercase();
    let stripped = lower
        .trim_start_matches("cwe-")
        .trim_start_matches("cwe_")
        .trim_start_matches("cwe");
    stripped
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect::<String>()
}
