/// Walk `target` with the (configurable) systems-hunt surface
/// scorer and return the ranked surface list — *without* the LLM
/// invariant/trigger/finding stages. Useful for plugging the surface
/// ranker into custom pipelines, scoring scripts, and the
/// libxml2-style live experiments.
///
/// `input` accepts the same JSON shape as
/// `run_systems_hunt_report` (`maxFiles`, `headBytes`,
/// `maxSurfaces`, ...). Index augmentation runs internally; failures
/// are silent.

/// Pick a sub-agent role for the invariant-extraction step based on the
/// surface mix in `context`. The first matching rule wins:
/// - Any Rust unsafe-region surface → UnsafeBlockReasoner
/// - Any FFI-boundary surface → FfiBoundaryReasoner
/// - Any resource-provenance surface in `.rs` → LifetimeAliasingReasoner
/// - Otherwise → Generic (no preamble change)

/// Augment surfaces with structural data from the code-index facade
/// when one is available. When no index backend is live (joern absent),
/// returns the surfaces unchanged. Fails soft on any backend error.
///
/// Use this from agentic flows that want signal beyond the
/// text-walking `gather_systems_context` produces. The legacy DAG
/// pipeline does not call this function — opt-in only.

/// Score-aware augmentation: contributes deterministic bumps to each
/// surface's `score` based on what the codeindex facade can prove
/// about it. Now called from the main `gather_systems_context` flow
/// (was opt-in via `try_augment_with_index`).
///
/// Bumps:
/// - Rust unsafe-region surface with N indexed unsafe blocks in the
///   same file: `+10 × min(N, 5)`.
/// - FFI-boundary surface with at least one indexed FFI hit: `+8`.
/// - Surface where joern's taint engine finds an attacker→sink path:
///   `+15` and prepends a "codeindex: taint reachable" reason.
///
/// All bumps are best-effort. When no joern backend is live, the
/// surfaces pass through unchanged.
use crate::findings::{Finding, Severity, StaticProofState};
use crate::modules::ToolExecutionContext;
use crate::runtime::SubagentRole;
use crate::runtime::{AgentQueryRequest, AgentRuntime, AgentToolPolicy};
use crate::structured_output::{
    parse_or_repair_required_structured_json, query_required_structured_json,
    StructuredJsonContract,
};
use crate::whitebox_static::{
    agent_tool_policy_for_input, mark_whitebox_static_findings, whitebox_static_profile_requested,
};
use anyhow::{Context, Result};
pub(crate) use build_surface_pack::*;
pub(crate) use classify_line::*;
pub(crate) use codeindex_has_joern_backend::*;
pub(crate) use collect_inventory::*;
pub(crate) use execute_trigger_synth::*;
pub(crate) use from_tool_input::*;
pub(crate) use gather_systems_context::*;
pub(crate) use hardening_signals::*;
pub(crate) use indexed_taint_path_found::*;
pub(crate) use invariants_from_input::*;
pub(crate) use normalize_deep_semantic_findings::*;
pub(crate) use normalize_systems_hunt_findings::*;
pub(crate) use parse_triggers::*;
pub(crate) use positive_usize::*;
pub(crate) use query_deep_semantic_findings::*;
pub(crate) use query_systems_invariants::*;
pub(crate) use run_deep_semantic_cwe_select::*;
pub(crate) use run_report::*;
pub(crate) use run_systems_trigger_synth::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
pub(crate) use string_array::*;
use uuid::Uuid;
mod build_surface_pack;
mod classify_line;
mod codeindex_has_joern_backend;
mod collect_inventory;
mod execute_trigger_synth;
mod from_tool_input;
mod gather_systems_context;
mod hardening_signals;
mod indexed_taint_path_found;
mod invariants_from_input;
mod normalize_deep_semantic_findings;
mod normalize_systems_hunt_findings;
mod output;
mod parse_triggers;
mod positive_usize;
mod query_deep_semantic_findings;
mod query_systems_invariants;
mod run_deep_semantic_cwe_select;
mod run_report;
mod run_systems_trigger_synth;
mod string_array;
mod systems_context_metadata;
#[cfg(test)]
mod tests;

pub use execute_trigger_synth::gather_surfaces;
pub use from_tool_input::SystemsContextOutput;
pub use output::execute_systems_hunt_tool;
pub use output::DeepSemanticCweOutput;
pub use output::DeepSemanticCweSelection;
pub use output::SystemsHuntPersistedRun;
pub use output::SystemsHuntReport;
pub(crate) use query_systems_invariants::score_with_index;
pub use query_systems_invariants::try_augment_with_index;
pub use run_report::run_systems_hunt_report;
pub use systems_context_metadata::RankedSystemsSurface;
pub use systems_context_metadata::SystemsCodeLocation;
pub use systems_context_metadata::SystemsContextMetadata;
pub use systems_context_metadata::SystemsHelperTemplate;
pub use systems_context_metadata::SystemsInvariant;
pub use systems_context_metadata::SystemsInvariantOutput;
pub use systems_context_metadata::SystemsSurfacePack;
pub use systems_context_metadata::SystemsSurfaceSignal;
pub use systems_context_metadata::SystemsTriggerHypothesis;
pub use systems_context_metadata::SystemsTriggerOutput;
