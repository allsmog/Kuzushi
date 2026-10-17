use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SystemsContextMetadata {
    pub codeql_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codeql_db_path: Option<String>,
    pub bash_probing_used: bool,
    /// Systems-language source prefixes inspected. Consult `inspection` before
    /// interpreting zero as absence: unreadable or omitted files are possible.
    #[serde(default)]
    pub systems_source_files: usize,
    /// Bounded standalone inspection receipt. Absent in legacy bundled output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inspection: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RankedSystemsSurface {
    pub id: String,
    pub file_path: String,
    pub start_line: u32,
    pub display_name: String,
    pub kind: String,
    pub score: i64,
    pub domains: Vec<String>,
    pub reasons: Vec<String>,
    pub attacker_controlled_fields: Vec<String>,
    pub hardening_signals: Vec<String>,
    pub evidence: Vec<SystemsSurfaceSignal>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SystemsSurfaceSignal {
    pub domain: String,
    pub line_number: u32,
    pub line_content: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SystemsSurfacePack {
    pub surface_id: String,
    pub anchor_file_path: String,
    pub anchor_start_line: u32,
    pub related_files: Vec<String>,
    pub unsafe_sites: Vec<SystemsCodeLocation>,
    pub resource_provenance_sites: Vec<SystemsCodeLocation>,
    pub hardening_sites: Vec<SystemsCodeLocation>,
    pub input_sites: Vec<SystemsCodeLocation>,
    pub helper_templates: Vec<SystemsHelperTemplate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SystemsCodeLocation {
    pub file_path: String,
    pub line: u32,
    pub snippet: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SystemsHelperTemplate {
    pub id: String,
    pub title: String,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SystemsInvariant {
    pub id: String,
    pub surface_id: String,
    pub kind: String,
    pub summary: String,
    pub statement: String,
    pub rationale: String,
    pub evidence: Vec<String>,
    pub attacker_controlled_fields: Vec<String>,
    pub cheap_verifiable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SystemsInvariantOutput {
    pub invariants: Vec<SystemsInvariant>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SystemsTriggerHypothesis {
    pub id: String,
    pub surface_id: String,
    pub ordered_steps: Vec<String>,
    pub boundary_assignments: BTreeMap<String, String>,
    pub state_preconditions: Vec<String>,
    pub attacker_controlled_fields: Vec<String>,
    pub expected_primitive: String,
    pub cheap_verifiable: bool,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SystemsTriggerOutput {
    pub triggers: Vec<SystemsTriggerHypothesis>,
}
