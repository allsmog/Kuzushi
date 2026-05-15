/// Logical role assigned to an agent call. Each role maps to one
/// [`ModelRoute`] in `models.toml`.
///
/// Adding a new role requires:
///   1. Add the variant here.
///   2. Add a `[roles.<snake_case>]` example in the docs above.
///   3. Update [`AgentRole::as_key`] / [`AgentRole::from_key`].

/// Loaded routing table.

/// Wraps an existing [`AgentRuntime`] and substitutes the model based on
/// the agent role. Implements `AgentRuntime` itself so legacy callers see
/// a transparent passthrough.
use crate::config::ConfigPaths;
use crate::findings::TriageOutcome;
use crate::options::{OptionScope, OptionTarget, ToolOptionStore};
use crate::runtime::{
    validate_model_spec, AgentLoopStep, AgentQueryRequest, AgentQueryResponse, AgentRuntime,
    AgentToolLoopRequest, LoopHistoryEntry, TriageRequest,
};
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
mod as_key;
mod query_blocking;
mod route_types;
mod routed_runtime_dispatch;
mod router_state;
#[cfg(test)]
mod tests;

pub use as_key::AgentRole;
pub use route_types::AgentRouter;
pub use route_types::ModelRoute;
pub use router_state::RoutedRuntime;
