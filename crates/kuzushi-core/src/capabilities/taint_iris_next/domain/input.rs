use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TaintIrisNextMode {
    Plan,
    Hunt,
}

impl TaintIrisNextMode {
    pub(crate) fn from_input(input: &Value) -> Result<Self> {
        match input.get("mode").and_then(Value::as_str).unwrap_or("plan") {
            "plan" => Ok(Self::Plan),
            "hunt" => Ok(Self::Hunt),
            other => anyhow::bail!(
                "taint-iris-next:hunt mode must be \"plan\" or \"hunt\", got {other:?}"
            ),
        }
    }

    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Hunt => "hunt",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TaintIrisNextCaps {
    pub(crate) max_catalog_entries: usize,
    pub(crate) max_candidates_per_cwe: usize,
    pub(crate) max_evidence_per_cwe: usize,
    pub(crate) max_files_per_query: usize,
    pub(crate) max_specs_per_cwe: usize,
    pub(crate) max_agent_findings: usize,
    /// Build-refusal ceiling for the cpg-rs backend: a stale/missing graph
    /// whose in-scope corpus exceeds this file count fails explicitly
    /// instead of grinding unbounded (scope with `targetSubdir` instead).
    pub(crate) max_cpg_source_files: usize,
    pub(crate) codeql_analyze_timeout_ms: usize,
    pub(crate) min_evidence_level: String,
}

#[derive(Debug, Clone)]
pub(crate) struct TaintIrisNextInput {
    pub(crate) threat_model: crate::capabilities::threat_model::ThreatModelSelection,
    pub(crate) mode: TaintIrisNextMode,
    pub(crate) backend: String,
    pub(crate) languages: Vec<String>,
    pub(crate) caps: TaintIrisNextCaps,
    pub(crate) max_budget_usd: Option<f64>,
    pub(crate) cwe_focus: Vec<String>,
    pub(crate) discover_signals: bool,
    pub(crate) target_subdir: Option<String>,
    pub(crate) allow_deterministic_fallback: bool,
    pub(crate) system_prompt: String,
    /// Operator-supplied catalog entries merged on top of the hardcoded
    /// `TAINT_IRIS_NEXT_CATALOG` before ranking. Carries threat-intel
    /// TOML entries through to the agent prompt — see
    /// `examples/threat-intel/redis-curated.toml` and
    /// `capabilities/threat_intel/application/dispatch.rs`.
    pub(crate) extra_catalog_entries: Vec<TaintIrisNextRankedCatalogEntry>,
}
