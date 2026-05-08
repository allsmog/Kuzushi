use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::modules) enum TaintIrisNextMode {
    Plan,
    Hunt,
}

impl TaintIrisNextMode {
    pub(in crate::modules) fn from_input(input: &Value) -> Result<Self> {
        match input.get("mode").and_then(Value::as_str).unwrap_or("plan") {
            "plan" => Ok(Self::Plan),
            "hunt" => Ok(Self::Hunt),
            other => anyhow::bail!(
                "taint-iris-next:hunt mode must be \"plan\" or \"hunt\", got {other:?}"
            ),
        }
    }

    pub(in crate::modules) fn as_str(&self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Hunt => "hunt",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::modules) struct TaintIrisNextCaps {
    pub(in crate::modules) max_catalog_entries: usize,
    pub(in crate::modules) max_candidates_per_cwe: usize,
    pub(in crate::modules) max_evidence_per_cwe: usize,
    pub(in crate::modules) max_files_per_query: usize,
    pub(in crate::modules) max_specs_per_cwe: usize,
    pub(in crate::modules) max_agent_findings: usize,
    pub(in crate::modules) codeql_analyze_timeout_ms: usize,
    pub(in crate::modules) min_evidence_level: String,
}

#[derive(Debug, Clone)]
pub(in crate::modules) struct TaintIrisNextInput {
    pub(in crate::modules) mode: TaintIrisNextMode,
    pub(in crate::modules) backend: String,
    pub(in crate::modules) languages: Vec<String>,
    pub(in crate::modules) caps: TaintIrisNextCaps,
    pub(in crate::modules) max_budget_usd: Option<f64>,
}
