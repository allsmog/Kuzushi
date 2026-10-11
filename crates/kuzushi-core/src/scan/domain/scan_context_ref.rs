//! Immutable supporting context carried by a finite discovery plan.
use crate::content_store::ObjectRef;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanContextRef {
    pub schema_version: u32,
    pub object: ObjectRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ScanContextDocument {
    pub schema_version: u32,
    pub target: String,
    pub source_identity: String,
    pub context_enrichment: Option<String>,
}
