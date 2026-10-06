use super::helpers::{
    entry_name, first_string, ingress_label, nonempty_string_field, resolved_targets, risk_label,
    source_label, NOT_MODELED_ZONE,
};
use super::model::{EntryPointCounts, EntryPointDisposition, EntryPointItem};
use crate::ui_view_models::viz_data::dfd::{string_array, string_field, DfdModel};
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) fn catalog_entries(
    doc: Option<&Value>,
    warnings: &mut Vec<String>,
) -> BTreeMap<String, EntryPointItem> {
    let Some(doc) = doc else {
        return BTreeMap::new();
    };
    let Some(rows) = doc.get("entryPoints").and_then(Value::as_array) else {
        warnings.push("extractor catalog malformed: entryPoints is not an array".to_string());
        return BTreeMap::new();
    };
    collect_unique_entries(
        rows,
        catalog_entry_from_value,
        "extractor catalog",
        warnings,
    )
}

pub(super) fn model_entries(
    doc: Option<&Value>,
    topology: &DfdModel,
    warnings: &mut Vec<String>,
) -> BTreeMap<String, EntryPointItem> {
    let Some(doc) = doc else {
        return BTreeMap::new();
    };
    let Some(value) = doc.pointer("/attackSurface/entryPoints") else {
        return BTreeMap::new();
    };
    let Some(rows) = value.as_array() else {
        warnings
            .push("threat model malformed: attackSurface.entryPoints is not an array".to_string());
        return BTreeMap::new();
    };
    collect_unique_entries(
        rows,
        |row| model_entry_from_value(row, topology),
        "threat model",
        warnings,
    )
}

fn collect_unique_entries<F>(
    rows: &[Value],
    mut parse: F,
    source: &str,
    warnings: &mut Vec<String>,
) -> BTreeMap<String, EntryPointItem>
where
    F: FnMut(&Value) -> Option<EntryPointItem>,
{
    let parsed = rows.iter().filter_map(&mut parse).collect::<Vec<_>>();
    let invalid = rows.len().saturating_sub(parsed.len());
    push_invalid_row_warning(source, invalid, warnings);
    insert_unique_entries(parsed, source, warnings)
}

fn insert_unique_entries(
    entries: Vec<EntryPointItem>,
    source: &str,
    warnings: &mut Vec<String>,
) -> BTreeMap<String, EntryPointItem> {
    let mut by_id = BTreeMap::new();
    let mut duplicates = 0;
    for entry in entries {
        if by_id.insert(entry.id.clone(), entry).is_some() {
            duplicates += 1;
        }
    }
    if duplicates > 0 {
        warnings.push(format!(
            "{source} contains {duplicates} duplicate stable id(s)"
        ));
    }
    by_id
}

fn push_invalid_row_warning(source: &str, invalid: usize, warnings: &mut Vec<String>) {
    if invalid > 0 {
        warnings.push(format!(
            "{source} contains {invalid} row(s) without a stable id"
        ));
    }
}

fn catalog_entry_from_value(value: &Value) -> Option<EntryPointItem> {
    Some(EntryPointItem {
        id: nonempty_string_field(value, "id")?,
        name: entry_name(value),
        kind: string_field(value, "kind").unwrap_or_else(|| "uncategorized".to_string()),
        trust_zone: NOT_MODELED_ZONE.to_string(),
        description: String::new(),
        ingress: ingress_label(value),
        source: source_label(value),
        source_framework: nonempty_string_field(value, "framework"),
        evidence: string_field(value, "evidence").unwrap_or_default(),
        risk: risk_label(value),
        disposition: EntryPointDisposition::ExtractedOnly,
        disposition_note: "not represented in the current threat model".to_string(),
        targets: Vec::new(),
        unresolved_target_count: 0,
    })
}

fn model_entry_from_value(value: &Value, topology: &DfdModel) -> Option<EntryPointItem> {
    let target_ids = string_array(value, "targetElementIds");
    let targets = resolved_targets(topology, &target_ids);
    Some(EntryPointItem {
        id: nonempty_string_field(value, "id")?,
        name: entry_name(value),
        kind: string_field(value, "kind").unwrap_or_else(|| "uncategorized".to_string()),
        trust_zone: string_field(value, "trustZone").unwrap_or_else(|| "unknown".to_string()),
        description: string_field(value, "description").unwrap_or_default(),
        ingress: ingress_label(value),
        source: source_label(value),
        source_framework: None,
        evidence: string_field(value, "evidence").unwrap_or_default(),
        risk: String::new(),
        disposition: EntryPointDisposition::ModelOnly,
        disposition_note: "threat-model row has no current catalog match".to_string(),
        unresolved_target_count: target_ids.len().saturating_sub(targets.len()),
        targets,
    })
}

pub(super) fn deprioritized_entries(doc: Option<&Value>) -> BTreeMap<String, String> {
    let rows = doc
        .and_then(|doc| {
            doc.pointer("/deprioritized")
                .or_else(|| doc.pointer("/coverage/deprioritized"))
        })
        .and_then(Value::as_array);
    rows.map_or_else(BTreeMap::new, |rows| {
        rows.iter().filter_map(deprioritized_entry).collect()
    })
}

fn deprioritized_entry(value: &Value) -> Option<(String, String)> {
    if value.get("parkedBy").and_then(Value::as_str) == Some("system") {
        return None;
    }
    let id = first_string(value, &["entryPointId", "entryPoint"])?;
    let reason = nonempty_string_field(value, "reason")?;
    Some((id, reason))
}

pub(super) fn entry_point_counts(
    catalog: &BTreeMap<String, EntryPointItem>,
    model: &BTreeMap<String, EntryPointItem>,
    deprioritized: &BTreeMap<String, String>,
) -> EntryPointCounts {
    let overlap = catalog.keys().filter(|id| model.contains_key(*id)).count();
    let deprioritized = catalog
        .keys()
        .filter(|id| !model.contains_key(*id) && deprioritized.contains_key(*id))
        .count();
    let model_only = model.len().saturating_sub(overlap);
    EntryPointCounts {
        extracted: catalog.len(),
        modeled: model.len(),
        overlap,
        deprioritized,
        unrepresented: catalog.len().saturating_sub(overlap + deprioritized),
        model_only,
        union: catalog.len() + model_only,
    }
}

pub(super) fn union_entries(
    catalog: BTreeMap<String, EntryPointItem>,
    mut model: BTreeMap<String, EntryPointItem>,
    deprioritized: &BTreeMap<String, String>,
) -> Vec<EntryPointItem> {
    let mut entries = catalog
        .into_values()
        .map(|entry| {
            let modeled = model.remove(&entry.id);
            classify_catalog_entry(entry, modeled, deprioritized)
        })
        .collect::<Vec<_>>();
    entries.extend(model.into_values());
    entries.sort_by(entry_sort_order);
    entries
}

fn classify_catalog_entry(
    mut catalog: EntryPointItem,
    modeled: Option<EntryPointItem>,
    deprioritized: &BTreeMap<String, String>,
) -> EntryPointItem {
    if let Some(modeled) = modeled {
        overlay_model_context(&mut catalog, modeled);
        return catalog;
    }
    if let Some(reason) = deprioritized.get(&catalog.id) {
        catalog.disposition = EntryPointDisposition::Deprioritized;
        catalog.disposition_note = reason.clone();
    }
    catalog
}

fn overlay_model_context(catalog: &mut EntryPointItem, modeled: EntryPointItem) {
    catalog.disposition = EntryPointDisposition::Modeled;
    catalog.disposition_note = "catalog row linked to current threat-model context".to_string();
    catalog.trust_zone = modeled.trust_zone;
    catalog.description = modeled.description;
    catalog.targets = modeled.targets;
    catalog.unresolved_target_count = modeled.unresolved_target_count;
}

fn entry_sort_order(left: &EntryPointItem, right: &EntryPointItem) -> std::cmp::Ordering {
    left.disposition
        .rank()
        .cmp(&right.disposition.rank())
        .then_with(|| left.kind.cmp(&right.kind))
        .then_with(|| left.name.cmp(&right.name))
        .then_with(|| left.id.cmp(&right.id))
}
