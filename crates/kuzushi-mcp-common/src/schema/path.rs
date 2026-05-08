use serde::{Deserialize, Serialize};

use super::Position;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    Call,
    ReachingDef,
    DataDependence,
    ControlFlow,
    Includes,
    References,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Path {
    pub steps: Vec<Position>,
    pub edges: Vec<EdgeKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sink: Option<String>,
}
