use super::*;
use serde::{Deserialize, Serialize};

pub(crate) const MAX_REGENERATION_FIELDS: usize = 8;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ContextRegenerationResponse {
    pub schema_version: u32,
    pub edits: Vec<ContextTextEdit>,
}

pub(crate) fn regeneration_fields(
    document: &Value,
    selected: &[String],
) -> Result<Vec<ContextTextField>> {
    anyhow::ensure!(
        (1..=MAX_REGENERATION_FIELDS).contains(&selected.len()),
        "Select one to eight context text fields"
    );
    let catalog = context_text_fields(document);
    let mut unique = BTreeSet::new();
    selected
        .iter()
        .map(|pointer| {
            anyhow::ensure!(
                unique.insert(pointer),
                "Context field was selected twice: {pointer}"
            );
            catalog
                .iter()
                .find(|field| &field.pointer == pointer)
                .cloned()
                .with_context(|| format!("Context field cannot be regenerated: {pointer}"))
        })
        .collect()
}

pub(crate) fn validate_regenerated_text(
    document: &Value,
    selected: &[String],
    response: &ContextRegenerationResponse,
) -> Result<Value> {
    anyhow::ensure!(
        response.schema_version == 1,
        "Unsupported context regeneration response version"
    );
    let _fields = regeneration_fields(document, selected)?;
    let requested = selected.iter().collect::<BTreeSet<_>>();
    let returned = response
        .edits
        .iter()
        .map(|edit| &edit.pointer)
        .collect::<BTreeSet<_>>();
    anyhow::ensure!(requested==returned && response.edits.len()==requested.len(), "Regeneration must return each selected field exactly once; protected and unselected fields cannot change");
    apply_context_text_edits(document, &response.edits)
}

#[cfg(test)]
mod tests;
