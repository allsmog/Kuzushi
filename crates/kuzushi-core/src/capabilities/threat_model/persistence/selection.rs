//! Explicit scan readers never resolve through the mutable active pointer.
use super::{load_threat_model_revision, try_load_persistent_threat_model, ThreatModelRef};
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub(crate) enum ThreatModelSelection {
    #[default]
    Active,
    None,
    Revision(ThreatModelRef),
}

impl ThreatModelSelection {
    pub(crate) fn from_input(input: &Value) -> Result<Self> {
        match selection_value(input)? {
            None => Ok(Self::Active),
            Some(Value::Null) => Ok(Self::None),
            Some(value) => parse_reference(value).map(Self::Revision),
        }
    }

    pub(crate) fn is_bound(&self) -> bool {
        !matches!(self, Self::Active)
    }
}

fn selection_value(input: &Value) -> Result<Option<&Value>> {
    let canonical = input.get("threatModelRef");
    let alias = input.get("threat_model_ref");
    if let (Some(left), Some(right)) = (canonical, alias) {
        anyhow::ensure!(left == right, "conflicting threatModelRef aliases");
    }
    Ok(canonical.or(alias))
}

fn parse_reference(value: &Value) -> Result<ThreatModelRef> {
    let reference: ThreatModelRef = serde_json::from_value(value.clone())
        .context("threatModelRef must be an immutable revision reference or null")?;
    super::ThreatModelId::parse(reference.model_id.as_str())?;
    super::ThreatModelRevisionId::parse(reference.revision_id.as_str())?;
    super::model_store::validate_sha256(&reference.sha256)?;
    Ok(reference)
}

pub(crate) fn load_selected_threat_model(
    root: &Path,
    selection: &ThreatModelSelection,
) -> Result<Option<Value>> {
    match selection {
        ThreatModelSelection::Active => try_load_persistent_threat_model(root),
        ThreatModelSelection::None => Ok(None),
        ThreatModelSelection::Revision(reference) => {
            load_exact_threat_model(root, reference).map(Some)
        }
    }
}

pub(crate) fn load_exact_threat_model(root: &Path, reference: &ThreatModelRef) -> Result<Value> {
    let loaded = load_threat_model_revision(root, &reference.model_id, Some(&reference.revision_id))?;
    anyhow::ensure!(loaded.model_ref == *reference, "bound threatModelRef failed immutable object verification");
    Ok(loaded.document)
}

#[cfg(test)]
pub(crate) mod tests;
