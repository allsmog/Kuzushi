use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TaintCweSelection {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) reason: String,
}
