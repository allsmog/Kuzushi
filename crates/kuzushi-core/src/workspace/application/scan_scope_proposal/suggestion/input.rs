//! A bounded inventory projection, never a second repository traversal.
use super::*;
use serde::Serialize;
use std::collections::BTreeMap;

pub(super) const MAX_PROMPT_BYTES: usize = 65_536;

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
) -> Result<ScopeModelInput> {
    anyhow::ensure!(
        priorities.len() <= 2048,
        "scope priorities exceed 2048 bytes"
    );
    let inspection = inventory
        .inspection
        .as_ref()
        .context("scope inventory membership is missing")?;
    let files = sample(&inspection.files, 512, 16_384)?;
    let supplied_files = files["items"].as_array().unwrap().len();
    let limitations = limitations(inventory, inspection.files.len(), supplied_files);
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
        "context":context_outline(context)?, "operatorPriorities":priorities,
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

fn sample<T: Serialize>(values: &[T], maximum: usize, byte_limit: usize) -> Result<Value> {
    let mut items = Vec::new();
    let mut remaining = byte_limit;
    for value in values.iter().take(maximum) {
        let bytes = serde_json::to_vec(value)?;
        if bytes.len() + 1 > remaining {
            continue;
        }
        remaining -= bytes.len() + 1;
        items.push(serde_json::from_slice::<Value>(&bytes)?);
    }
    Ok(json!({"total":values.len(), "omitted":values.len()-items.len(), "items":items}))
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
        let segments: Vec<_> = file.split('/').collect();
        let depth = segments.len().saturating_sub(1).min(2);
        let path = segments[..depth].join("/");
        *groups.entry(path).or_default() += 1;
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
    sample(&fields, 5, 8192)
}

fn limitations(inventory: &RepositoryInventory, total: usize, supplied: usize) -> Vec<String> {
    let mut lines = vec!["Each inventory, architecture and current-scope section reports its own omitted rows. Uninspected content is not source understanding.".into()];
    lines.push(format!("The proposal receives {supplied} of {total} enumerated file names; remaining files still require coverage review."));
    if let Some(truncated) = &inventory.truncation {
        lines.push(format!("Inventory is partial: {}", truncated.reason));
    }
    lines
}
