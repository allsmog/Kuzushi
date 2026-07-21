use crate::modules::ToolExecutionContext;
use crate::runtime::{AgentQueryRequest, AgentRuntime};
use crate::structured_output::StructuredJsonContract;
use anyhow::{Context, Result};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

mod adapters;
mod application;
mod domain;
#[cfg(test)]
mod normalize_document_tests;
mod persistence;
#[cfg(test)]
mod tests;

pub(crate) use adapters::*;
pub(crate) use application::*;
pub(crate) use domain::*;
pub(crate) use persistence::*;

pub use adapters::execute_threat_model_tool;
pub use persistence::{
    load_persistent_threat_model, persistent_threat_model_path, resolve_threat_model,
    save_persistent_threat_model, try_load_persistent_threat_model, ResolvedThreatModel,
    ThreatModelResolvedVia,
};
