use crate::evidence::static_evidence::{StaticEvidenceNode, StaticEvidenceStore};
use crate::findings::{Finding, Severity, StaticProofState, TriageVerdict};
use crate::modules::ToolExecutionContext;
use crate::runtime::{AgentQueryRequest, AgentRuntime};
use crate::structured_output::{
    query_required_structured_json_with_cost, CostedStructuredJson, StructuredJsonContract,
};
use crate::whitebox_static::try_whitebox_static_policy_for_target;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

mod adapters;
mod application;
mod domain;
mod persistence;
#[cfg(test)]
mod registry_dispatch_fixture;
#[cfg(test)]
mod tests;

pub(crate) use adapters::*;
pub(crate) use application::*;
pub(crate) use domain::*;
pub(crate) use persistence::*;

pub use adapters::{
    run_ndiff_extract_fix_pattern, run_ndiff_fetch_cve, run_ndiff_hunt_variants, run_variant_hunt,
    run_variant_lift_pattern,
};
pub use application::{derive_whitebox_variant_patterns, hunt_whitebox_static_variants};
pub use domain::{WhiteboxVariantPattern, WhiteboxVariantSearchReport};
