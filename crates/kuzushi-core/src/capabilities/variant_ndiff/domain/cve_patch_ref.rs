use super::*;

pub(crate) const DEFAULT_VENDOR_PATHS: &[&str] = &[
    "node_modules",
    "vendor",
    "third_party",
    "third-party",
    "deps",
    "external",
];

pub(crate) const VARIANT_SIGNATURE_SYSTEM_PROMPT: &str = r#"You are Kuzushi's Variant Hunter pattern lifter.
Return only JSON matching:
{"source":"where untrusted data enters","sink":"dangerous API or operation","missingGuard":"missing validation or sanitization","languages":["language"],"keywords":["grep keyword"],"description":"portable pattern description"}.
Base the signature on source evidence only."#;

pub(crate) const VARIANT_HUNT_SYSTEM_PROMPT: &str = r#"You are Kuzushi's variant analysis agent.
Return only JSON matching:
{"variants":[{"filePath":"relative/path","startLine":1,"severity":"ERROR|WARNING|INFO","message":"short finding summary","confidence":"HIGH|MEDIUM|LOW","rationale":"source-grounded reason","cwe":["CWE-..."]}]}.
Report only HIGH or MEDIUM confidence variants you verified in source."#;

pub(crate) const NDIFF_FIX_PATTERN_SYSTEM_PROMPT: &str = r#"You are Kuzushi's N-day fix-pattern extractor.
Return only JSON matching:
{"fixShape":"what the patch added","vulnerableShape":"pre-patch vulnerable shape","cwe":["CWE-..."],"languages":["language"],"keywords":["grep keyword"],"detectionQuery":"ripgrep or AST-grep sketch","description":"portable pattern description","confidence":"HIGH|MEDIUM|LOW"}.
Analyze only the supplied existing diff and advisory metadata. Do not invent facts, generate a code patch or reproducer, execute source or begin follow-up discovery. The result is an unaccepted draft requiring human review."#;

pub(crate) const NDIFF_HUNT_SYSTEM_PROMPT: &str = r#"You are Kuzushi's N-day variant hunter.
Return only JSON matching:
{"variants":[{"filePath":"relative/path","startLine":1,"severity":"ERROR|WARNING|INFO","message":"short finding summary","confidence":"HIGH|MEDIUM|LOW","rationale":"source-grounded reason","cwe":["CWE-..."]}]}.
Report only code that still has the vulnerable pre-patch shape and lacks the fix shape."#;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CvePatchRef {
    pub(crate) url: String,
    pub(crate) kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) title: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CveRecord {
    pub(crate) id: String,
    pub(crate) description: String,
    #[serde(default)]
    pub(crate) cwes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cvss_score: Option<f64>,
    #[serde(default)]
    pub(crate) affected: Vec<String>,
    #[serde(default)]
    pub(crate) patches: Vec<CvePatchRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) published_at: Option<String>,
    pub(crate) source: String,
    #[serde(default)]
    pub(crate) raw: Value,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PersistedRun {
    pub(crate) run_id: String,
    pub(crate) findings_db: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WhiteboxVariantSearchReport {
    pub count: usize,
    pub patterns: Vec<WhiteboxVariantPattern>,
    pub variants: Vec<Finding>,
    pub deterministic: bool,
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub truncation_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WhiteboxVariantPattern {
    pub original_fingerprint: String,
    pub rule_id: String,
    pub file_path: String,
    pub start_line: u32,
    pub source_tokens: Vec<String>,
    pub sink_tokens: Vec<String>,
    pub missing_guard_tokens: Vec<String>,
    pub keywords: Vec<String>,
    pub description: String,
}
