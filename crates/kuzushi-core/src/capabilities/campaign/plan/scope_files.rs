//! Legacy scope files use one bounded inventory, never a second filesystem walk.
use super::{CampaignShard, PlanRequest, PlannedJob, SCOPE_FILE_TOOLS};
use crate::modules::ToolExecutionContext;
use crate::workspace::{InventoryInspection, RepositoryInventory};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

mod membership;

const MAX_INVENTORY_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;
// The existing chunked consumer reads at most 4 MiB from a scope file.
const MAX_SCOPE_FILE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Default)]
pub(super) struct CampaignScopeFiles {
    paths: BTreeMap<String, String>,
    receipt: Option<Value>,
}

impl CampaignScopeFiles {
    pub(super) fn prepare(
        root: &Path,
        request: &PlanRequest,
        jobs: &[PlannedJob],
        ctx: &ToolExecutionContext<'_>,
    ) -> Result<Self> {
        if !SCOPE_FILE_TOOLS.contains(&request.tool.as_str()) {
            return Ok(Self::default());
        }
        let shards = scoped_shards(jobs);
        if shards.is_empty() {
            return Ok(Self::default());
        }
        let inventory = collect_inventory(root, ctx)?;
        let inspection = require_complete_enumeration(&inventory)?;
        let members = membership::collect(inspection, &shards, ctx)?;
        let artifact = inventory_artifact(&inventory)?;
        let relative = format!(
            ".kuzushi/v3/campaigns/{}/scope/inventory.json",
            request.campaign_id
        );
        let paths = write_scope_files(root, request, &members, ctx)?;
        ensure_active(ctx)?;
        crate::workspace::write_workspace_file(root, &relative, &artifact)?;
        Ok(Self {
            paths,
            receipt: Some(inventory_receipt(
                &relative, &artifact, inspection, &inventory,
            )),
        })
    }

    pub(super) fn path(&self, shard: &str) -> Option<String> {
        self.paths.get(shard).cloned()
    }

    pub(super) fn attach_receipt(&self, plan: &mut Value) {
        if let Some(receipt) = &self.receipt {
            plan["scopeInventory"] = receipt.clone();
        }
    }
}

fn scoped_shards(jobs: &[PlannedJob]) -> BTreeMap<String, &CampaignShard> {
    jobs.iter()
        .filter(|job| !job.shard.paths.is_empty())
        .map(|job| (job.shard.name.clone(), &job.shard))
        .collect()
}

pub(super) fn ensure_active(ctx: &ToolExecutionContext<'_>) -> Result<()> {
    anyhow::ensure!(
        !ctx.is_cancelled(),
        "campaign:plan canceled; no executable plan was published"
    );
    Ok(())
}

fn collect_inventory(root: &Path, ctx: &ToolExecutionContext<'_>) -> Result<RepositoryInventory> {
    let mut heartbeat = crate::progress::HeartbeatGate::new(std::time::Duration::from_secs(1));
    let mut progress = |entries| {
        if heartbeat.ready() {
            emit_progress(ctx, entries);
        }
    };
    let inventory =
        crate::workspace::build_repository_inventory_with_observer(root, &mut progress, &|| {
            ctx.is_cancelled()
        })?;
    ensure_active(ctx)?;
    Ok(inventory)
}

fn emit_progress(ctx: &ToolExecutionContext<'_>, entries: usize) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool-progress",
                "campaign:plan",
                format!("repository inventory: {entries} entries examined"),
            )
            .emit();
    }
}

fn require_complete_enumeration(inventory: &RepositoryInventory) -> Result<&InventoryInspection> {
    let inspection = inventory
        .inspection
        .as_ref()
        .context("scope inventory has no inspection receipt")?;
    anyhow::ensure!(
        inspection.enumeration_complete == Some(true),
        "scope inventory file enumeration is incomplete: {}; narrow the repository before planning scope-file jobs",
        inventory.truncation.as_ref().map_or("unknown extent", |value| &value.reason)
    );
    Ok(inspection)
}

fn inventory_artifact(inventory: &RepositoryInventory) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec_pretty(inventory)?;
    anyhow::ensure!(
        bytes.len() <= MAX_INVENTORY_ARTIFACT_BYTES,
        "scope inventory receipt exceeds 16 MiB; narrow the repository before planning"
    );
    Ok(bytes)
}

fn write_scope_files(
    root: &Path,
    request: &PlanRequest,
    members: &BTreeMap<String, Vec<String>>,
    ctx: &ToolExecutionContext<'_>,
) -> Result<BTreeMap<String, String>> {
    let mut paths = BTreeMap::new();
    for (name, files) in members {
        ensure_active(ctx)?;
        let relative = format!(
            ".kuzushi/v3/campaigns/{}/scope/{name}.txt",
            request.campaign_id
        );
        let body = files.join("\n") + "\n";
        anyhow::ensure!(
            body.len() <= MAX_SCOPE_FILE_BYTES,
            "shard {name:?} scope file exceeds the consumer's 4 MiB limit; narrow the shard"
        );
        crate::workspace::write_workspace_file(root, &relative, body.as_bytes())?;
        paths.insert(name.clone(), relative);
    }
    Ok(paths)
}

fn inventory_receipt(
    relative: &str,
    bytes: &[u8],
    inspection: &InventoryInspection,
    inventory: &RepositoryInventory,
) -> Value {
    json!({
        "schemaVersion":1,
        "path":relative,
        "sha256":crate::worker_protocol::sha256_digest(bytes).0,
        "enumeration":inspection.enumeration,
        "enumerationComplete":inspection.enumeration_complete,
        "enumeratedFiles":inspection.files.len(),
        "entries":inspection.entries,
        "inspectedBytes":inspection.inspected_bytes,
        "maxEntries":inspection.max_entries,
        "maxInspectedBytes":inspection.max_inspected_bytes,
        "maxFileInspectionBytes":inspection.max_file_inspection_bytes,
        "omittedPaths":inspection.omitted_paths.len(),
        "truncatedFiles":inspection.truncated_files.len(),
        "inspectionTruncation":inventory.truncation,
        "limitations":"Membership uses enumerated regular files. Ignored paths and uninspected or truncated content remain disclosed in the receipt. This planning inventory does not establish complete repository analysis or freeze source for execution."
    })
}

pub(super) fn summary_note(plan: &Value) -> String {
    let Some(receipt) = plan.get("scopeInventory") else {
        return String::new();
    };
    format!(
        "\nScope inventory: {} enumerated files; {} omitted paths; {} truncated file prefixes.\n{}\nReceipt: {}",
        receipt["enumeratedFiles"], receipt["omittedPaths"], receipt["truncatedFiles"],
        receipt["limitations"].as_str().unwrap_or_default(),
        receipt["path"].as_str().unwrap_or_default()
    )
}

#[cfg(test)]
mod tests;
