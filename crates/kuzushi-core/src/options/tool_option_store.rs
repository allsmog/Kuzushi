use super::OptionBinding;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ToolOptionStore {
    pub(crate) bindings: BTreeMap<OptionBinding, BTreeMap<String, Value>>,
}
