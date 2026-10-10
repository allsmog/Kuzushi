use crate::findings::{Finding, Severity, StaticProofState};
use crate::modules::ToolExecutionContext;
use crate::runtime::{AgentQueryRequest, AgentRuntime, AgentToolPolicy};
use crate::static_proof_validator::{
    static_proof_claim_from_whitebox_schema, validate_static_proof_claim, StaticProofValidation,
};
use crate::structured_output::{
    query_required_structured_json_with_cost, CostedStructuredJson, StructuredJsonContract,
};
use crate::whitebox_static::{
    agent_tool_policy_for_input_and_target, mark_whitebox_static_findings,
    whitebox_static_profile_requested, whitebox_static_proof_state_from_input,
    whitebox_static_triage_prompt_block, whitebox_static_triage_system_prompt,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

mod adapters;
mod application;
mod domain;
mod persistence;
#[cfg(test)]
mod tests;

pub(crate) use adapters::*;
pub(crate) use application::*;
pub use domain::{
    AgenticInventoryCoverage, AgenticSastPersistedRun, AgenticSastReport, AgenticScopeReceipt,
};
pub(crate) use domain::{AgenticSastInput, DEFAULT_AGENTIC_MODEL_TURNS};
pub(crate) use persistence::*;
