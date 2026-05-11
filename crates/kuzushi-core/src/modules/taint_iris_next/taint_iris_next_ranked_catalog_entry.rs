use super::*;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::modules) struct TaintIrisNextRankedCatalogEntry {
    pub(in crate::modules) cwe: String,
    pub(in crate::modules) name: String,
    pub(in crate::modules) taint_class: String,
    pub(in crate::modules) languages: Vec<String>,
    pub(in crate::modules) source_signals: Vec<String>,
    pub(in crate::modules) sink_signals: Vec<String>,
    pub(in crate::modules) sanitizer_signals: Vec<String>,
    pub(in crate::modules) structural_queries: Vec<String>,
    /// LLM-curated regex markers the `:catalog` tool emits for this
    /// CWE. Fed into the discovery sweep at hunt time via
    /// `OwnedMarkerSpec` so codebase-shape patterns (e.g. pgcrypto's
    /// `pullf_*`, libxml2's `xmlParse*`) reach discovery without a
    /// code change. Empty for static-fallback entries and for legacy
    /// catalogs predating C2; both round-trip cleanly via
    /// `skip_serializing_if`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in crate::modules) regex_markers: Vec<TaintIrisNextRegexMarker>,
    pub(in crate::modules) score: i32,
    pub(in crate::modules) reasons: Vec<String>,
}

/// Codebase-shape regex marker carried on a ranked catalog entry. The
/// `:catalog` tool emits these so the discovery sweep at `:hunt` time
/// can match parser-layer / sink-layer call shapes specific to this
/// codebase without a static `MARKERS`-table edit.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::modules) struct TaintIrisNextRegexMarker {
    pub(in crate::modules) pattern: String,
    pub(in crate::modules) kind: String,
    pub(in crate::modules) languages: Vec<String>,
    pub(in crate::modules) marker: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::modules) struct TaintIrisNextStructuralQuery {
    pub(in crate::modules) id: String,
    pub(in crate::modules) cwe: String,
    pub(in crate::modules) taint_class: String,
    pub(in crate::modules) role: String,
    pub(in crate::modules) pattern: String,
    pub(in crate::modules) languages: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::modules) struct TaintIrisNextArtifactStatus {
    pub(in crate::modules) ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::modules) path: Option<String>,
    pub(in crate::modules) reason: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::modules) struct TaintIrisNextBackendChoice {
    pub(in crate::modules) requested: String,
    pub(in crate::modules) selected: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::modules) codeql_db_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::modules) corroborate_with_codeql: Option<bool>,
    pub(in crate::modules) structural_tool: String,
    pub(in crate::modules) warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub(in crate::modules) struct TaintIrisNextPlan {
    pub(in crate::modules) target: PathBuf,
    pub(in crate::modules) scan_root: PathBuf,
    pub(in crate::modules) repo_root: PathBuf,
    pub(in crate::modules) mode: TaintIrisNextMode,
    pub(in crate::modules) caps: TaintIrisNextCaps,
    pub(in crate::modules) languages: Vec<String>,
    pub(in crate::modules) context_status: TaintIrisNextArtifactStatus,
    pub(in crate::modules) threat_model_status: TaintIrisNextArtifactStatus,
    pub(in crate::modules) repo_context: Option<Value>,
    pub(in crate::modules) threat_model: Option<Value>,
    pub(in crate::modules) catalog: Vec<TaintIrisNextRankedCatalogEntry>,
    pub(in crate::modules) structural_queries: Vec<TaintIrisNextStructuralQuery>,
    pub(in crate::modules) prompt_catalog: String,
    pub(in crate::modules) backend: TaintIrisNextBackendChoice,
    pub(in crate::modules) max_budget_usd: Option<f64>,
    /// Operator-supplied CWE allow-list propagated from
    /// `TaintIrisNextInput::cwe_focus`. Empty when no filter was
    /// requested. Surfaced into the agent prompt so the model knows
    /// which CWE classes the catalog has been narrowed to.
    pub(in crate::modules) cwe_focus: Vec<String>,
    /// Per-target source/sink + entry-point primitives discovered by
    /// `source_sink_discovery::run`. Empty when discovery was disabled
    /// or no markers matched. Used as a ranking signal during catalog
    /// rerank and surfaced into the agent prompt so the model can
    /// ground its CWE picks in primitives that actually exist in the
    /// codebase rather than the static catalog's a-priori guess.
    pub(in crate::modules) discovered_signals: DiscoveredSignals,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::modules) struct TaintIrisNextCandidate {
    pub(in crate::modules) id: String,
    pub(in crate::modules) cwe: String,
    pub(in crate::modules) taint_class: String,
    pub(in crate::modules) track: String,
    pub(in crate::modules) role: String,
    pub(in crate::modules) kind: String,
    pub(in crate::modules) pattern: String,
    pub(in crate::modules) file_path: String,
    pub(in crate::modules) line: u32,
    pub(in crate::modules) snippet: String,
    pub(in crate::modules) language: String,
    pub(in crate::modules) confidence: String,
    pub(in crate::modules) catalog_signal: String,
    pub(in crate::modules) source: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::modules) struct TaintIrisNextEvidence {
    pub(in crate::modules) cwe: String,
    pub(in crate::modules) taint_class: String,
    pub(in crate::modules) track: String,
    pub(in crate::modules) role: String,
    pub(in crate::modules) pattern: String,
    pub(in crate::modules) file_path: String,
    pub(in crate::modules) line: u32,
    pub(in crate::modules) snippet: String,
    pub(in crate::modules) language: String,
    pub(in crate::modules) confidence: String,
    pub(in crate::modules) catalog_signal: String,
    pub(in crate::modules) evidence_level: String,
    pub(in crate::modules) source: String,
    pub(in crate::modules) candidate_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::modules) linked_story_id: Option<String>,
}
