/// Walk `target` with the configurable systems-hunt surface scorer and return
/// the ranked surface list without the LLM invariant/trigger/finding stages.
///
/// `input` accepts the same JSON shape as `run_systems_hunt_report`
/// (`maxFiles`, `headBytes`, `maxSurfaces`, ...). Index augmentation runs
/// internally; failures are soft.
use crate::findings::{Finding, Severity, StaticProofState};
use crate::modules::ToolExecutionContext;
use crate::proof::whitebox_policy::{
    agent_tool_policy_for_input, mark_whitebox_static_findings, whitebox_static_profile_requested,
};
use crate::runtime::SubagentRole;
use crate::runtime::{AgentQueryRequest, AgentRuntime, AgentToolPolicy};
use crate::structured_output::{
    parse_or_repair_required_structured_json, query_required_structured_json,
    StructuredJsonContract,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

mod adapters;
mod application;
mod domain;
#[cfg(test)]
mod tests;

pub(crate) use adapters::*;
pub(crate) use application::*;
pub(crate) use domain::*;

pub use adapters::{execute_systems_hunt_tool, gather_surfaces};
#[cfg(test)]
pub(crate) use application::score_with_index;
pub use application::{run_systems_hunt_report, try_augment_with_index};
pub use domain::{
    DeepSemanticCweOutput, DeepSemanticCweSelection, RankedSystemsSurface, SystemsCodeLocation,
    SystemsContextMetadata, SystemsContextOutput, SystemsHelperTemplate, SystemsHuntPersistedRun,
    SystemsHuntReport, SystemsInvariant, SystemsInvariantOutput, SystemsSurfacePack,
    SystemsSurfaceSignal, SystemsTriggerHypothesis, SystemsTriggerOutput,
};
