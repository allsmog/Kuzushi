use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FocusArea {
    pub id: String,
    pub name: String,
    pub rationale: String,
    pub trust_boundary: String,
    #[serde(default)]
    pub seed_files: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenQuestion {
    pub kind: String,
    pub source: String,
    pub impact: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_artifact: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MapRunbookOutput {
    pub schema_version: String,
    #[serde(default)]
    pub focus_areas: Vec<FocusArea>,
    #[serde(default)]
    pub entry_points: Vec<serde_json::Value>,
    #[serde(default)]
    pub assets: Vec<serde_json::Value>,
    #[serde(default)]
    pub trust_boundaries: Vec<serde_json::Value>,
    #[serde(default)]
    pub threats: Vec<serde_json::Value>,
    #[serde(default)]
    pub open_questions: Vec<OpenQuestion>,
    #[serde(default)]
    pub partial: bool,
}

impl MapRunbookOutput {
    pub fn partial_with_question(question: OpenQuestion) -> Self {
        Self {
            schema_version: "map.output.v1".to_string(),
            focus_areas: Vec::new(),
            entry_points: Vec::new(),
            assets: Vec::new(),
            trust_boundaries: Vec::new(),
            threats: Vec::new(),
            open_questions: vec![question],
            partial: true,
        }
    }
}
