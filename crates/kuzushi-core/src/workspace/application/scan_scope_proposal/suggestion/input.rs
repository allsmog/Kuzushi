//! A bounded inventory projection, never a second repository traversal.
use super::*;
use serde::Serialize;
use std::collections::BTreeMap;
mod file_selection;

pub(super) const MAX_PROMPT_BYTES: usize = 65_536;
const MAX_CONTEXT_OUTLINE_BYTES: usize = 8192;

pub(super) struct ScopeModelInput {
    pub document: Value,
    pub supplied_files: usize,
    pub inventoried_files: usize,
    pub limitations: Vec<String>,
}

pub(super) fn build(
    inventory: &RepositoryInventory,
    review: &ScanScopeReview,
    context: Option<&Value>,
    priorities: &str,
    selection: Option<&Value>,
) -> Result<ScopeModelInput> {
    validate_priorities(priorities)?;
    let inspection = inventory
        .inspection
        .as_ref()
        .context("scope inventory membership is missing")?;
    let files = file_selection::sample(&inspection.files, selection)?;
    let supplied_files = files["items"].as_array().unwrap().len();
    let context = context_outline(context)?;
    let mut limitations = limitations(inventory, inspection.files.len(), supplied_files, &context);
    limitations.extend(file_selection::summary(&files));
    let document = json!({
        "schemaVersion":1, "source":review.record.source,
        "inventoryHash":review.record.inventory_hash,
        "rootName":inventory.root_name, "files":files,
        "directoryGroups":directory_groups(&inspection.files)?,
        "languages":sample(&inventory.languages,32,4096)?,
        "manifests":sample(&inventory.manifests,96,8192)?,
        "frameworks":sample(&inventory.frameworks,32,4096)?,
        "entryPoints":sample(&inventory.entrypoints,32,4096)?,
        "currentScopes":sample(&review.record.draft.scopes,8,4096)?,
        "operatorExclusions":sample(&review.record.draft.exclusions,128,4096)?,
        "context":context, "operatorPriorities":priorities,
        "limitations":limitations,
    });
    ensure_bounded_document(&document)?;
    Ok(ScopeModelInput {
        document,
        supplied_files,
        inventoried_files: inspection.files.len(),
        limitations,
    })
}

pub(super) fn validate_priorities(priorities: &str) -> Result<()> {
    anyhow::ensure!(
        priorities.len() <= 2048,
        "scope priorities exceed 2048 bytes"
    );
    Ok(())
}

fn sample<T: Serialize>(values: &[T], maximum: usize, byte_limit: usize) -> Result<Value> {
    sample_candidates(
        values.iter().take(maximum),
        values.len(),
        maximum,
        byte_limit,
    )
}

fn sample_candidates<T: Serialize>(
    values: impl IntoIterator<Item = T>,
    total: usize,
    maximum: usize,
    byte_limit: usize,
) -> Result<Value> {
    let mut items = Vec::new();
    let mut remaining = byte_limit;
    for value in values {
        if items.len() == maximum {
            break;
        }
        let bytes = serde_json::to_vec(&value)?;
        if bytes.len() + 1 > remaining {
            continue;
        }
        remaining -= bytes.len() + 1;
        items.push(serde_json::from_slice::<Value>(&bytes)?);
    }
    Ok(json!({"total":total, "omitted":total-items.len(), "items":items}))
}

pub(super) fn validate_file_selection(value: Option<&Value>) -> Result<()> {
    file_selection::validate(value)
}

fn ensure_bounded_document(document: &Value) -> Result<()> {
    anyhow::ensure!(
        serde_json::to_vec(document)?.len() <= MAX_PROMPT_BYTES,
        "scope input exceeds its 64 KiB limit; no model request was made"
    );
    Ok(())
}

fn directory_groups(files: &[String]) -> Result<Value> {
    let mut groups: BTreeMap<String, usize> = BTreeMap::new();
    for file in files {
        *groups
            .entry(file_selection::group(file).into())
            .or_default() += 1;
    }
    let rows: Vec<_> = groups
        .into_iter()
        .map(
            |(path, files)| json!({"path":if path.is_empty() { "." } else { &path },"files":files}),
        )
        .collect();
    sample(&rows, 96, 8192)
}

fn context_outline(context: Option<&Value>) -> Result<Value> {
    let Some(document) = context else {
        return Ok(Value::Null);
    };
    let pointers = [
        "/systemContext",
        "/contextSummary",
        "/dfd/nodes",
        "/dfd/flows",
        "/dfd/trustBoundaries",
        "/attackSurface/entryPoints",
    ];
    let fields: Vec<_> = pointers
        .iter()
        .filter_map(|pointer| {
            document
                .pointer(pointer)
                .map(|value| json!({"field":pointer,"value":value}))
        })
        .collect();
    sample(&fields, pointers.len(), MAX_CONTEXT_OUTLINE_BYTES)
}

fn context_input_summary(context: &Value) -> String {
    if context.is_null() {
        return "Architecture context: omitted.".into();
    }
    let total = context["total"].as_u64().unwrap();
    let omitted = context["omitted"].as_u64().unwrap();
    format!(
        "Context sections: {}/{total}; omitted {omitted}. Architecture outline bound: {} KiB.",
        total - omitted,
        MAX_CONTEXT_OUTLINE_BYTES / 1024
    )
}

fn limitations(
    inventory: &RepositoryInventory,
    total: usize,
    supplied: usize,
    context: &Value,
) -> Vec<String> {
    let mut lines = vec![context_input_summary(context), "Each inventory, architecture and current-scope section reports its own omitted rows. Uninspected content is not source understanding.".into()];
    lines.push(format!("The proposal receives {supplied} of {total} enumerated file names; remaining files still require coverage review."));
    if let Some(truncated) = &inventory.truncation {
        lines.push(format!("Inventory is partial: {}", truncated.reason));
    }
    lines
}
