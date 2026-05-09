use super::*;

#[derive(Debug, Deserialize)]
pub(crate) struct CodeqlPhysicalLocation {
    #[serde(default, rename = "artifactLocation")]
    pub(crate) artifact_location: Option<CodeqlArtifactLocation>,
    #[serde(default)]
    pub(crate) region: Option<CodeqlRegion>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CodeqlArtifactLocation {
    #[serde(default)]
    pub(crate) uri: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CodeqlRegion {
    #[serde(default, rename = "startLine")]
    pub(crate) start_line: Option<u32>,
    #[serde(default)]
    pub(crate) snippet: Option<CodeqlSarifMessage>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CodeqlCodeFlow {
    #[serde(default, rename = "threadFlows")]
    pub(crate) thread_flows: Vec<CodeqlThreadFlow>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CodeqlThreadFlow {
    #[serde(default)]
    pub(crate) locations: Vec<CodeqlThreadFlowLocation>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CodeqlThreadFlowLocation {
    #[serde(default)]
    pub(crate) message: Option<CodeqlSarifMessage>,
    #[serde(default)]
    pub(crate) location: Option<CodeqlNestedLocation>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CodeqlNestedLocation {
    #[serde(default)]
    pub(crate) message: Option<CodeqlSarifMessage>,
    #[serde(default, rename = "physicalLocation")]
    pub(crate) physical_location: Option<CodeqlPhysicalLocation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CodeqlFlowStep {
    pub(crate) file_path: String,
    pub(crate) line: u32,
    pub(crate) message: Option<String>,
    pub(crate) snippet: Option<String>,
}

#[derive(Debug, Default)]
pub(crate) struct CodeqlStaticEvidenceIndex {
    pub(crate) nodes_indexed: usize,
    pub(crate) edges_indexed: usize,
    pub(crate) node_ids: Vec<String>,
    pub(crate) edge_ids: Vec<String>,
}
