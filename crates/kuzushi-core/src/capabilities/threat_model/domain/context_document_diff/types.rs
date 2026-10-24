use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextDocumentDiff {
    pub schema_version: u32,
    pub changes: Vec<ContextValueDifference>,
    pub reordered_collections: Vec<ContextCollectionOrderDifference>,
    pub source_claims: ContextSourceClaims,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextSourceClaims {
    pub before: BTreeMap<String, Value>,
    pub after: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextValueDifference {
    pub section: ContextDifferenceSection,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    pub matching: ContextDifferenceMatching,
    pub field: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before_pointer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_pointer: Option<String>,
    #[serde(
        default,
        deserialize_with = "present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub before: Option<Value>,
    #[serde(
        default,
        deserialize_with = "present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub after: Option<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ContextDifferenceSection {
    Architecture,
    SecurityContext,
    Questions,
    Inputs,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ContextDifferenceMatching {
    Id,
    Position,
    AmbiguousPosition,
    DocumentField,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextCollectionOrderDifference {
    pub collection: String,
    pub before: Vec<String>,
    pub after: Vec<String>,
}

fn present_value<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(deserializer).map(Some)
}
