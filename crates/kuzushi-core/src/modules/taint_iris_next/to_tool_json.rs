use super::*;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::modules) struct TaintIrisNextLabeledSpec {
    pub(in crate::modules) id: String,
    pub(in crate::modules) cwe: String,
    pub(in crate::modules) taint_class: String,
    pub(in crate::modules) track: String,
    pub(in crate::modules) role: String,
    pub(in crate::modules) kind: String,
    pub(in crate::modules) api_name: String,
    pub(in crate::modules) pattern: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::modules) file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::modules) line: Option<u32>,
    pub(in crate::modules) confidence: String,
    pub(in crate::modules) rationale: String,
    pub(in crate::modules) catalog_signal: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::modules) struct TaintIrisNextLinkedStory {
    pub(in crate::modules) id: String,
    pub(in crate::modules) cwe: String,
    pub(in crate::modules) taint_class: String,
    pub(in crate::modules) track: String,
    pub(in crate::modules) evidence_level: String,
    pub(in crate::modules) file_path: String,
    pub(in crate::modules) language: String,
    pub(in crate::modules) source_candidate_id: String,
    pub(in crate::modules) sink_candidate_id: String,
    pub(in crate::modules) source_line: u32,
    pub(in crate::modules) sink_line: u32,
    pub(in crate::modules) shared_tokens: Vec<String>,
    pub(in crate::modules) rationale: String,
    /// Function names appearing on the source→sink flow as
    /// interprocedural callees, captured from joern's flow steps
    /// (`JoernStep.code`). Empty for the heuristic linker, which
    /// has no notion of a call graph. Drives Thread B1's
    /// relaxed-name body-inlining: the agent prompt pulls the body
    /// of each callee so upstream bound-check helpers
    /// (`pgp_mpi_alloc`, `prepare_room`, etc.) are visible inline
    /// without an extra MCP round-trip.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in crate::modules) callees: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::modules) struct TaintIrisNextEvidenceResult {
    pub(in crate::modules) backend: String,
    pub(in crate::modules) tool: String,
    pub(in crate::modules) evidence: Vec<TaintIrisNextEvidence>,
    pub(in crate::modules) candidates: Vec<TaintIrisNextCandidate>,
    pub(in crate::modules) linked_stories: Vec<TaintIrisNextLinkedStory>,
    pub(in crate::modules) labeled_specs: Vec<TaintIrisNextLabeledSpec>,
    pub(in crate::modules) query_count: usize,
    pub(in crate::modules) candidate_counts: BTreeMap<String, usize>,
    pub(in crate::modules) labeled_spec_counts: BTreeMap<String, usize>,
    pub(in crate::modules) linked_story_count: usize,
    pub(in crate::modules) backend_path_count: usize,
    pub(in crate::modules) structural_engine: String,
    pub(in crate::modules) triage_summary: Value,
    pub(in crate::modules) outcome: String,
    pub(in crate::modules) warnings: Vec<String>,
    pub(in crate::modules) artifacts: Value,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(in crate::modules) struct TaintIrisNextPersistedRun {
    pub(in crate::modules) run_id: String,
    pub(in crate::modules) findings_db: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::modules) struct TaintIrisNextReport {
    pub(in crate::modules) target: String,
    pub(in crate::modules) status: String,
    pub(in crate::modules) mode: String,
    pub(in crate::modules) count: usize,
    pub(in crate::modules) findings: Vec<Finding>,
    pub(in crate::modules) review_candidates: Vec<Finding>,
    pub(in crate::modules) selected_cwes: Vec<Value>,
    pub(in crate::modules) persisted: Option<TaintIrisNextPersistedRun>,
    pub(in crate::modules) cost_usd: f64,
    #[serde(skip)]
    pub(in crate::modules) ok: bool,
    #[serde(skip)]
    pub(in crate::modules) output: String,
    #[serde(skip)]
    pub(in crate::modules) data: Value,
}

impl TaintIrisNextReport {
    pub(in crate::modules) fn to_tool_json(&self) -> Value {
        let mut data = self.data.clone();
        if let Value::Object(object) = &mut data {
            object.insert("persisted".to_string(), json!(self.persisted));
        }
        json!({
            "ok": self.ok,
            "output": self.output,
            "data": data,
            "costUsd": self.cost_usd,
        })
    }
}
