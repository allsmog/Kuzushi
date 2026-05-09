use super::*;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TaintIrisNextRankedCatalogEntry {
    pub(crate) cwe: String,
    pub(crate) name: String,
    pub(crate) taint_class: String,
    pub(crate) languages: Vec<String>,
    pub(crate) source_signals: Vec<String>,
    pub(crate) sink_signals: Vec<String>,
    pub(crate) sanitizer_signals: Vec<String>,
    pub(crate) structural_queries: Vec<String>,
    pub(crate) score: i32,
    pub(crate) reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TaintIrisNextStructuralQuery {
    pub(crate) id: String,
    pub(crate) cwe: String,
    pub(crate) taint_class: String,
    pub(crate) role: String,
    pub(crate) pattern: String,
    pub(crate) languages: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TaintIrisNextArtifactStatus {
    pub(crate) ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) path: Option<String>,
    pub(crate) reason: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TaintIrisNextBackendChoice {
    pub(crate) requested: String,
    pub(crate) selected: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) codeql_db_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) corroborate_with_codeql: Option<bool>,
    pub(crate) structural_tool: String,
    pub(crate) warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct TaintIrisNextPlan {
    pub(crate) target: PathBuf,
    pub(crate) scan_root: PathBuf,
    pub(crate) repo_root: PathBuf,
    pub(crate) mode: TaintIrisNextMode,
    pub(crate) caps: TaintIrisNextCaps,
    pub(crate) languages: Vec<String>,
    pub(crate) context_status: TaintIrisNextArtifactStatus,
    pub(crate) threat_model_status: TaintIrisNextArtifactStatus,
    pub(crate) repo_context: Option<Value>,
    pub(crate) threat_model: Option<Value>,
    pub(crate) catalog: Vec<TaintIrisNextRankedCatalogEntry>,
    pub(crate) structural_queries: Vec<TaintIrisNextStructuralQuery>,
    pub(crate) prompt_catalog: String,
    pub(crate) backend: TaintIrisNextBackendChoice,
    pub(crate) max_budget_usd: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TaintIrisNextCandidate {
    pub(crate) id: String,
    pub(crate) cwe: String,
    pub(crate) taint_class: String,
    pub(crate) track: String,
    pub(crate) role: String,
    pub(crate) kind: String,
    pub(crate) pattern: String,
    pub(crate) file_path: String,
    pub(crate) line: u32,
    pub(crate) snippet: String,
    pub(crate) language: String,
    pub(crate) confidence: String,
    pub(crate) catalog_signal: String,
    pub(crate) source: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TaintIrisNextEvidence {
    pub(crate) cwe: String,
    pub(crate) taint_class: String,
    pub(crate) track: String,
    pub(crate) role: String,
    pub(crate) pattern: String,
    pub(crate) file_path: String,
    pub(crate) line: u32,
    pub(crate) snippet: String,
    pub(crate) language: String,
    pub(crate) confidence: String,
    pub(crate) catalog_signal: String,
    pub(crate) evidence_level: String,
    pub(crate) source: String,
    pub(crate) candidate_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) linked_story_id: Option<String>,
}
