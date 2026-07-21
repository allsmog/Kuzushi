use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RepositoryInventory {
    pub root_name: String,
    pub languages: Vec<InventoryLanguage>,
    pub source_files: Vec<InventorySourceFile>,
    pub manifests: Vec<InventoryFile>,
    pub dependency_manifests: Vec<InventoryFile>,
    pub config_files: Vec<InventoryFile>,
    pub frameworks: Vec<InventoryFramework>,
    pub entrypoints: Vec<InventoryEntrypoint>,
    pub routes_controllers: Vec<InventoryRouteController>,
    pub generated_vendor_paths: Vec<InventoryPathClassification>,
    /// Present when a walk budget was exhausted: the inventory is usable but
    /// PARTIAL, and downstream surfaces must never label it complete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncation: Option<InventoryTruncation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InventoryTruncation {
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InventoryLanguage {
    pub name: String,
    pub files: usize,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InventorySourceFile {
    pub path: String,
    pub language: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InventoryFile {
    pub path: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InventoryFramework {
    pub name: String,
    pub language: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InventoryEntrypoint {
    pub kind: String,
    pub path: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InventoryRouteController {
    pub kind: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InventoryPathClassification {
    pub path: String,
    pub kind: String,
    pub reason: String,
}

#[derive(Debug, Default)]
pub(crate) struct InventoryBuilder {
    pub(crate) languages: BTreeMap<String, LanguageAccumulator>,
    pub(crate) source_files: BTreeMap<String, InventorySourceFile>,
    pub(crate) manifests: BTreeMap<String, InventoryFile>,
    pub(crate) dependency_manifests: BTreeMap<String, InventoryFile>,
    pub(crate) config_files: BTreeMap<String, InventoryFile>,
    pub(crate) frameworks: BTreeMap<(String, String), FrameworkAccumulator>,
    pub(crate) entrypoints: BTreeMap<String, InventoryEntrypoint>,
    pub(crate) routes_controllers: BTreeMap<String, InventoryRouteController>,
    pub(crate) generated_vendor_paths: BTreeMap<String, InventoryPathClassification>,
}

#[derive(Debug, Default)]
pub(crate) struct LanguageAccumulator {
    pub(crate) files: usize,
    pub(crate) bytes: u64,
}

#[derive(Debug, Default)]
pub(crate) struct FrameworkAccumulator {
    pub(crate) evidence: BTreeSet<String>,
}
