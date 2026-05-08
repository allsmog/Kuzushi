use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadDefinitionInput {
    pub name: String,
    /// Optional file hint to scope the search.
    #[serde(default)]
    pub hint_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadDefinitionOutput {
    pub name: String,
    pub file: String,
    pub line: u32,
    pub kind: String,
    pub signature: String,
    pub source: String,
    /// Other candidate locations the heuristic found, in case the first
    /// pick is wrong.
    pub also_seen: Vec<DefinitionEntry>,
}
