use super::*;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TaintIrisNextLabeledSpec {
    pub(crate) id: String,
    pub(crate) cwe: String,
    pub(crate) taint_class: String,
    pub(crate) track: String,
    pub(crate) role: String,
    pub(crate) kind: String,
    pub(crate) api_name: String,
    pub(crate) pattern: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) line: Option<u32>,
    pub(crate) confidence: String,
    pub(crate) rationale: String,
    pub(crate) catalog_signal: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TaintIrisNextLinkedStory {
    pub(crate) id: String,
    pub(crate) cwe: String,
    pub(crate) taint_class: String,
    pub(crate) track: String,
    pub(crate) evidence_level: String,
    pub(crate) file_path: String,
    pub(crate) language: String,
    pub(crate) source_candidate_id: String,
    pub(crate) sink_candidate_id: String,
    pub(crate) source_line: u32,
    pub(crate) sink_line: u32,
    pub(crate) shared_tokens: Vec<String>,
    pub(crate) rationale: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) callees: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TaintIrisNextEvidenceResult {
    pub(crate) backend: String,
    pub(crate) tool: String,
    pub(crate) evidence: Vec<TaintIrisNextEvidence>,
    pub(crate) candidates: Vec<TaintIrisNextCandidate>,
    pub(crate) linked_stories: Vec<TaintIrisNextLinkedStory>,
    pub(crate) labeled_specs: Vec<TaintIrisNextLabeledSpec>,
    pub(crate) query_count: usize,
    pub(crate) candidate_counts: BTreeMap<String, usize>,
    pub(crate) labeled_spec_counts: BTreeMap<String, usize>,
    pub(crate) linked_story_count: usize,
    pub(crate) backend_path_count: usize,
    pub(crate) structural_engine: String,
    pub(crate) triage_summary: Value,
    pub(crate) outcome: String,
    pub(crate) warnings: Vec<String>,
    pub(crate) artifacts: Value,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TaintIrisNextPersistedRun {
    pub(crate) run_id: String,
    pub(crate) findings_db: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TaintIrisNextReport {
    pub(crate) target: String,
    pub(crate) status: String,
    pub(crate) mode: String,
    pub(crate) count: usize,
    pub(crate) findings: Vec<Finding>,
    pub(crate) review_candidates: Vec<Finding>,
    pub(crate) selected_cwes: Vec<Value>,
    pub(crate) persisted: Option<TaintIrisNextPersistedRun>,
    pub(crate) cost_usd: f64,
    #[serde(skip)]
    pub(crate) ok: bool,
    #[serde(skip)]
    pub(crate) output: String,
    #[serde(skip)]
    pub(crate) data: Value,
}

impl TaintIrisNextReport {
    pub(crate) fn to_tool_json(&self) -> Value {
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
