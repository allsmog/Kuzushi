use crate::findings::{Finding, Severity, StaticProofState};
use crate::modules::ToolExecutionContext;
use crate::proof::whitebox_policy::{
    agentic_hunter_thinking_level, default_whitebox_static_agent_tool_policy,
    mark_whitebox_static_findings, whitebox_static_profile_requested,
};
use crate::runtime::{AgentQueryRequest, AgentQueryResponse, AgentRuntime};
use crate::structured_output::{
    parse_or_repair_required_structured_json, repair_request_from, StructuredJsonContract,
};
use crate::workspace::artifact_kb::{ArtifactKnowledgePromptContext, ArtifactKnowledgeSnippet};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

mod adapters;
mod application;
mod domain;
#[cfg(test)]
mod query_carlini_actor_tests;
#[cfg(test)]
mod tests;

pub(crate) use adapters::*;
pub(crate) use application::*;
pub(crate) use domain::*;

pub use application::{run_carlini_threat_hunt, run_carlini_threat_hunt_report};
pub use domain::{CarliniThreatHuntPersistedRun, CarliniThreatHuntReport};
