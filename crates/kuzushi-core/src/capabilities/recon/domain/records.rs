use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReconHost {
    pub id: String,
    pub workspace_id: String,
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReconService {
    pub id: String,
    pub host_id: String,
    pub port: u16,
    pub proto: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReconNote {
    pub id: String,
    pub workspace_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_id: Option<String>,
    pub ntype: String,
    pub data: Value,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReconPersisted {
    pub(crate) workspace_id: String,
    pub(crate) db: String,
    pub(crate) host_count: usize,
    pub(crate) service_count: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReconReport {
    pub(crate) tool: String,
    pub(crate) target: String,
    pub(crate) hosts: Vec<ReconHost>,
    pub(crate) services: Vec<ReconService>,
    pub(crate) notes: Vec<ReconNote>,
    pub(crate) persisted: ReconPersisted,
    /// How many entries `.kuzushi/scope.toml` refused, for the import verbs
    /// that read a dump of many entries and gate each one. `Some(0)` is a
    /// complete import; `None` belongs to the verbs that take a single target,
    /// whose scope refusal is a dispatch error rather than a skipped entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) skipped_out_of_scope: Option<usize>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) subdomains: Vec<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) fingerprint: BTreeMap<String, Value>,
}
