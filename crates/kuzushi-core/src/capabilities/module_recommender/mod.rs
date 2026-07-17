use crate::attack_surface::{build_attack_surface_map_from_inventory, AttackSurfaceMap};
use crate::findings::{Finding, FindingStore, Severity};
use crate::modules::ToolExecutionContext;
use crate::repository_inventory::{build_repository_inventory, RepositoryInventory};
use crate::runtime::AgentRuntime;
use crate::threat_model::{persistent_threat_model_path, try_load_persistent_threat_model};
use crate::workspace::WorkspaceTarget;
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

mod adapters;
mod application;
mod component_classify;
mod domain;
mod model_ranking;
mod rule_catalog;
mod threat_model_signals;
#[cfg(test)]
mod tests;

pub(crate) use adapters::execute_module_recommender_tool;
pub(crate) use application::build_recommendation_report_ranked;
#[cfg(test)]
pub(crate) use application::build_recommendation_report;
pub(crate) use domain::*;
pub(crate) use model_ranking::ModelRanking;
