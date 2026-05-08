use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompileDb {
    pub path: PathBuf,
    pub generator: Generator,
    pub entries: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Generator {
    PreExisting,
    Cmake,
    Bear,
    InterceptBuild,
    None,
}
