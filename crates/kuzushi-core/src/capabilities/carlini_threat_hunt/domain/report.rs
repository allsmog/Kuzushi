use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CarliniThreatHuntPersistedRun {
    pub run_id: String,
    pub findings_db: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CarliniThreatHuntReport {
    pub target: String,
    pub count: usize,
    pub actors: usize,
    pub actor_runs: usize,
    pub prompt_inventory_files: usize,
    pub threat_focused_prompt_files: usize,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persisted: Option<CarliniThreatHuntPersistedRun>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kb_context: Option<ArtifactKnowledgePromptContext>,
    pub cost_usd: f64,
}
