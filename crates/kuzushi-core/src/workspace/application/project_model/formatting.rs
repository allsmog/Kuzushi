use super::PROJECT_MODEL_SCHEMA_VERSION;
use serde::Serialize;

pub(super) fn value_hash(value: &impl Serialize) -> String {
    serde_json::to_string(value)
        .map(|body| crate::static_evidence::static_content_hash(&body))
        .unwrap_or_else(|_| "invalid:unserializable".to_string())
}

pub(super) fn join_language_names(
    languages: &[crate::repository_inventory::InventoryLanguage],
) -> String {
    names_or_none(languages.iter().map(|language| language.name.as_str()))
}

pub(super) fn join_framework_names(
    frameworks: &[crate::repository_inventory::InventoryFramework],
) -> String {
    names_or_none(frameworks.iter().map(|framework| framework.name.as_str()))
}

fn names_or_none<'a>(names: impl Iterator<Item = &'a str>) -> String {
    let names = names.collect::<Vec<_>>();
    if names.is_empty() {
        "none".to_string()
    } else {
        names.join(", ")
    }
}

pub(super) fn default_project_model_schema_version() -> u32 {
    PROJECT_MODEL_SCHEMA_VERSION
}
