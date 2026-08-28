//! Resource-claim policy for repeated scan trials.
//!
//! The campaign dispatcher remains the process-isolation boundary. This
//! module only decides how many detached children may run concurrently for a
//! fully prepared scan input.

use crate::modules::ModuleRegistry;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

mod task_claims;

use task_claims::registered_task_claim;

pub const MAX_CAMPAIGN_WORKERS: usize = 8;
const SAST_SCAN_TOOL: &str = "sast:scan";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ParallelSafety {
    Isolated,
    SharedRead,
    WorkspaceExclusive { resource: String },
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanTaskParallelClaim {
    pub task: String,
    pub safety: ParallelSafety,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParallelSafetyResolution {
    pub requested_workers: usize,
    pub effective_workers: usize,
    pub dispatcher_cap: usize,
    pub safety: ParallelSafety,
    pub claims: Vec<ScanTaskParallelClaim>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clamp_reason: Option<String>,
}

pub fn resolve_parallel_safety(
    registry: &ModuleRegistry,
    tool: &str,
    prepared_input: &Value,
    requested_workers: usize,
) -> Result<ParallelSafetyResolution> {
    anyhow::ensure!(requested_workers >= 1, "--workers must be at least 1");
    registry
        .resolve_tool(tool)
        .with_context(|| format!("parallel safety cannot resolve unknown tool {tool:?}"))?;
    if tool != SAST_SCAN_TOOL {
        return Ok(unknown_tool_resolution(tool, requested_workers));
    }
    resolve_sast_parallel_safety(prepared_input, requested_workers)
}

fn resolve_sast_parallel_safety(
    input: &Value,
    requested_workers: usize,
) -> Result<ParallelSafetyResolution> {
    let mode = input
        .get("taskMode")
        .and_then(Value::as_str)
        .unwrap_or("auto");
    if mode != "manual" {
        return Ok(automatic_selection_resolution(requested_workers));
    }
    let tasks = selected_tasks(input);
    if tasks.is_empty() {
        return Ok(unresolved_selection_resolution(requested_workers));
    }
    let claims = tasks
        .iter()
        .map(|task| claim_for_task(task, input))
        .collect::<Vec<_>>();
    Ok(resolution_for_claims(requested_workers, claims))
}

fn selected_tasks(input: &Value) -> Vec<String> {
    input
        .get("tasks")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|task| !task.is_empty())
        .map(str::to_string)
        .collect()
}

fn resolution_for_claims(
    requested_workers: usize,
    claims: Vec<ScanTaskParallelClaim>,
) -> ParallelSafetyResolution {
    let safety = aggregate_safety(&claims);
    let policy_reason = policy_clamp_reason(&claims, &safety);
    let cap_reason = dispatcher_cap_reason(requested_workers);
    let effective_workers = match safety {
        ParallelSafety::Unknown | ParallelSafety::WorkspaceExclusive { .. } => 1,
        ParallelSafety::Isolated | ParallelSafety::SharedRead => {
            requested_workers.min(MAX_CAMPAIGN_WORKERS)
        }
    };
    ParallelSafetyResolution {
        requested_workers,
        effective_workers,
        dispatcher_cap: MAX_CAMPAIGN_WORKERS,
        safety,
        claims,
        clamp_reason: policy_reason.or(cap_reason),
    }
}

fn aggregate_safety(claims: &[ScanTaskParallelClaim]) -> ParallelSafety {
    if claims
        .iter()
        .any(|claim| claim.safety == ParallelSafety::Unknown)
    {
        return ParallelSafety::Unknown;
    }
    if let Some(resource) = claims.iter().find_map(exclusive_resource) {
        return ParallelSafety::WorkspaceExclusive { resource };
    }
    if claims
        .iter()
        .any(|claim| claim.safety == ParallelSafety::SharedRead)
    {
        ParallelSafety::SharedRead
    } else {
        ParallelSafety::Isolated
    }
}

fn exclusive_resource(claim: &ScanTaskParallelClaim) -> Option<String> {
    match &claim.safety {
        ParallelSafety::WorkspaceExclusive { resource } => Some(resource.clone()),
        _ => None,
    }
}

fn policy_clamp_reason(
    claims: &[ScanTaskParallelClaim],
    safety: &ParallelSafety,
) -> Option<String> {
    match safety {
        ParallelSafety::Unknown => claims
            .iter()
            .find(|claim| claim.safety == ParallelSafety::Unknown)
            .map(|claim| {
                format!(
                    "task {} has unresolved parallel resource claims",
                    claim.task
                )
            }),
        ParallelSafety::WorkspaceExclusive { resource } => claims
            .iter()
            .find(|claim| exclusive_resource(claim).as_deref() == Some(resource.as_str()))
            .map(|claim| {
                format!(
                    "task {} is workspace-exclusive on resource {resource}",
                    claim.task
                )
            }),
        ParallelSafety::Isolated | ParallelSafety::SharedRead => None,
    }
}

fn dispatcher_cap_reason(requested_workers: usize) -> Option<String> {
    (requested_workers > MAX_CAMPAIGN_WORKERS).then(|| {
        format!(
            "requested workers {requested_workers} exceed dispatcher cap {MAX_CAMPAIGN_WORKERS}"
        )
    })
}

fn claim_for_task(task: &str, input: &Value) -> ScanTaskParallelClaim {
    let (canonical, safety) = match registered_task_claim(task) {
        Some(("taint-iris-next", _)) => ("taint-iris-next", taint_backend_safety(input)),
        Some(claim) => claim,
        None => (task, ParallelSafety::Unknown),
    };
    ScanTaskParallelClaim {
        task: canonical.to_string(),
        safety,
    }
}

fn taint_backend_safety(input: &Value) -> ParallelSafety {
    match input
        .get("backend")
        .and_then(Value::as_str)
        .unwrap_or("auto")
    {
        "cpg" | "cpg-rs" => workspace_exclusive("workspace-cpg-rs-graph"),
        "codeql" => workspace_exclusive("workspace-codeql-database"),
        "structural" | "semgrep" | "language" => ParallelSafety::SharedRead,
        _ => ParallelSafety::Unknown,
    }
}

fn workspace_exclusive(resource: &str) -> ParallelSafety {
    ParallelSafety::WorkspaceExclusive {
        resource: resource.to_string(),
    }
}

fn unknown_tool_resolution(tool: &str, requested_workers: usize) -> ParallelSafetyResolution {
    unknown_resolution(
        requested_workers,
        format!("tool {tool} has no scan-task parallel resource contract"),
    )
}

fn automatic_selection_resolution(requested_workers: usize) -> ParallelSafetyResolution {
    unknown_resolution(
        requested_workers,
        "sast:scan automatic task selection has unresolved parallel resource claims".to_string(),
    )
}

fn unresolved_selection_resolution(requested_workers: usize) -> ParallelSafetyResolution {
    unknown_resolution(
        requested_workers,
        "sast:scan manual task selection did not resolve any task claims".to_string(),
    )
}

fn unknown_resolution(requested_workers: usize, reason: String) -> ParallelSafetyResolution {
    ParallelSafetyResolution {
        requested_workers,
        effective_workers: 1,
        dispatcher_cap: MAX_CAMPAIGN_WORKERS,
        safety: ParallelSafety::Unknown,
        claims: Vec::new(),
        clamp_reason: Some(reason),
    }
}

#[cfg(test)]
mod tests;
