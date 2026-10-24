use super::*;
use crate::repository_inventory::RepositoryInventory;

const MAX_PROMPT_INVENTORY_BYTES: usize = 512 * 1024;
const MAX_OMISSION_EXAMPLES: usize = 20;

#[derive(Debug, Clone)]
pub(crate) struct PromptRepositoryInventory {
    pub(crate) files: Vec<String>,
    pub(crate) receipt: Value,
}

impl PromptRepositoryInventory {
    pub(crate) fn collect(
        root: &Path,
        limit: usize,
        ctx: &ToolExecutionContext<'_>,
    ) -> Result<Self> {
        Self::from_inventory(collect_context_inventory(root, ctx)?, limit)
    }

    pub(crate) fn from_inventory(inventory: RepositoryInventory, limit: usize) -> Result<Self> {
        let inspection = inventory
            .inspection
            .as_ref()
            .context("Threat-model inventory requires an inspection receipt")?;
        let mut paths = inspection.files.iter().collect::<Vec<_>>();
        paths.sort_by_key(|path| (path.split('/').count(), *path));
        let files = paths.into_iter().take(limit).cloned().collect::<Vec<_>>();
        let receipt = inventory_receipt(&inventory, &files, limit)?;
        let prepared = Self { files, receipt };
        anyhow::ensure!(
            prepared.prompt_data()?.len() <= MAX_PROMPT_INVENTORY_BYTES,
            "Repository filename inventory exceeds 512 KiB; reduce maxElements or select a narrower scope"
        );
        Ok(prepared)
    }

    pub(crate) fn prompt_data(&self) -> Result<String> {
        serde_json::to_string(&self.receipt)
            .context("Could not encode prepared repository filename inventory")
    }

    pub(crate) fn disclosure(&self) -> String {
        let extent = match self.receipt["enumerationComplete"].as_bool() {
            Some(true) => "complete",
            Some(false) => "partial",
            None => "unknown",
        };
        format!("Repository filename list: {} / {} enumerated paths; enumeration {extent}. Other source sections have separate limits. No complete repository coverage claim.", self.files.len(), self.receipt["enumeratedFiles"])
    }
}

pub(crate) fn collect_context_inventory(
    root: &Path,
    ctx: &ToolExecutionContext<'_>,
) -> Result<RepositoryInventory> {
    anyhow::ensure!(
        !ctx.is_cancelled(),
        "Threat-model inventory preparation canceled"
    );
    let mut heartbeat = crate::progress::HeartbeatGate::new(std::time::Duration::from_secs(1));
    let inventory = crate::repository_inventory::build_repository_inventory_with_observer(
        root,
        &mut |entries| {
            if heartbeat.ready() {
                emit_inventory_progress(ctx, entries);
            }
        },
        &|| ctx.is_cancelled(),
    )?;
    anyhow::ensure!(
        !ctx.is_cancelled(),
        "Threat-model inventory preparation canceled"
    );
    Ok(inventory)
}

fn inventory_receipt(
    inventory: &RepositoryInventory,
    files: &[String],
    limit: usize,
) -> Result<Value> {
    let inspection = inventory
        .inspection
        .as_ref()
        .context("Threat-model inventory requires an inspection receipt")?;
    let listed = serde_json::to_string(files)?;
    Ok(json!({
        "schemaVersion":1,"purpose":"base-synthesis-filename-list","enumeration":inspection.enumeration,
        "enumerationComplete":inspection.enumeration_complete,
        "enumeratedFiles":inspection.files.len(),"listedFiles":files.len(),
        "unlistedFiles":inspection.files.len().saturating_sub(files.len()),
        "listedPaths":files,
        "listLimit":limit,"listOrder":"depth_then_path",
        "listedPathsSha256":crate::options::prompt_content_sha256(&listed),
        "pathBasis":"analysis-root-relative",
        "entriesExamined":inspection.entries,"maxEntries":inspection.max_entries,
        "inspectedBytes":inspection.inspected_bytes,"maxInspectedBytes":inspection.max_inspected_bytes,
        "maxFileInspectionBytes":inspection.max_file_inspection_bytes,
        "omittedPathCount":inspection.omitted_paths.len(),
        "omittedPathExamples":inspection.omitted_paths.iter().take(MAX_OMISSION_EXAMPLES).collect::<Vec<_>>(),
        "omittedPathExamplesComplete":inspection.omitted_paths.len()<=MAX_OMISSION_EXAMPLES,
        "truncatedFileCount":inspection.truncated_files.len(),
        "truncatedFileExamples":inspection.truncated_files.iter().take(MAX_OMISSION_EXAMPLES).collect::<Vec<_>>(),
        "truncatedFileExamplesComplete":inspection.truncated_files.len()<=MAX_OMISSION_EXAMPLES,
        "truncation":inventory.truncation,
        "selectionKind":"filename-list","selectedMembershipKnown":true,
        "membershipPolicy":membership_policy(&inspection.enumeration),
        "completeRepositoryCoverage":false
    }))
}

fn membership_policy(enumeration: &str) -> &'static str {
    match enumeration {
        "git-index" => "Git-index paths only. Untracked and ignored files are outside this list; their count is unknown.",
        "filesystem" => "Filesystem enumeration with built-in excludes. Git ignore rules are not evaluated.",
        _ => "Enumeration was interrupted or is unverified. Membership outside the recorded list is unknown.",
    }
}

fn emit_inventory_progress(ctx: &ToolExecutionContext<'_>, entries: usize) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool-progress",
                "threat-model:build",
                format!("repository inventory · {entries} entries examined"),
            )
            .emit();
    }
}

#[cfg(test)]
mod tests;
