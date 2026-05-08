use super::prelude::*;
use super::*;

impl VulnSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sarif => "sarif",
            Self::Ainalysis => "ainalysis",
            Self::AinalysisMulti => "ainalysis-multi",
            Self::DiffAnalyzer => "diff-analyzer",
            Self::Infer => "infer",
            Self::Fuzzing => "fuzzing",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "sarif" => Some(Self::Sarif),
            "ainalysis" => Some(Self::Ainalysis),
            "ainalysis-multi" | "ainalysis_multi" => Some(Self::AinalysisMulti),
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
            "semgrep" | "codeql" | "secret-scan" | "iac-scan" | "dep-hygiene" => Self::Sarif,
            "systems-hunt" | "carlini-threat-hunt" => Self::Ainalysis,
            "full-mode-multi" => Self::AinalysisMulti,
            "variant-ndiff" => Self::DiffAnalyzer,
            "infer" => Self::Infer,
            _ => Self::Ainalysis,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    pub id: Option<i64>,
    pub scan_id: Option<String>,
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
    /// Most-recent empirical verification, when present. Loaded by
    /// `FindingStore::get_finding_by_*` from the `verifications` side
    /// table; in-memory `Finding`s built via `Finding::new_tool` leave
    /// this `None` until persisted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<PersistedVerification>,
    pub created_at: String,
    /// Discovery channel — populated automatically from `tool` if not
    /// set explicitly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vuln_source: Option<VulnSource>,
    /// Cross-channel collision key. Two findings with the same
    /// `dedup_key` in the same scan are treated as the same underlying
    /// vulnerability — the higher-severity one wins, the tool list
    /// merges. Computed from `(file, line/16, normalized_cwe)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dedup_key: Option<String>,
}

pub(crate) const DEDUP_LINE_BUCKET: u32 = 16;

pub fn compute_dedup_key(file: &str, line: u32, cwe: Option<&str>) -> String {
    let bucket = line / DEDUP_LINE_BUCKET;
    let normalised_file = file.trim_start_matches("./");
    let cwe_part = cwe.map(normalize_cwe).unwrap_or_else(|| "*".to_string());
    format!("{normalised_file}:{bucket}:{cwe_part}")
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
