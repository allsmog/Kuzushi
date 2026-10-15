//! Exact scanner-context bytes retained independently of renderer changes.
use crate::capabilities::threat_model::ThreatModelRef;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ThreatModelDigestDocument {
    pub schema_version: u32,
    pub kind: String,
    pub target: String,
    pub source_identity: String,
    pub threat_model_ref: ThreatModelRef,
    pub preview: Value,
}
