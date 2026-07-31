use super::dfd::{dfd_model, rows_at, string_array, string_field};
use super::{DfdModel, ShellApp};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct EntryPointBreakdown {
    pub entries: Vec<EntryPointItem>,
    pub kinds: Vec<EntryPointGroup>,
    pub zones: Vec<EntryPointGroup>,
    pub linked_target_count: usize,
    pub target_count: usize,
    pub empty_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EntryPointGroup {
    pub name: String,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EntryPointItem {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub trust_zone: String,
    pub description: String,
    pub ingress: String,
    pub source: String,
    pub evidence: String,
    pub targets: Vec<EntryPointTarget>,
    pub unresolved_target_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EntryPointTarget {
    pub id: String,
    pub label: String,
}

pub(crate) fn entry_point_breakdown(app: &ShellApp) -> EntryPointBreakdown {
    let doc = super::super::threat_model_doc(app);
    let Some(doc) = doc.as_ref() else {
        return empty_breakdown();
    };
    let topology = dfd_model(app);
    entry_point_breakdown_from_doc(doc, &topology)
}

fn entry_point_breakdown_from_doc(
    doc: &serde_json::Value,
    topology: &DfdModel,
) -> EntryPointBreakdown {
    let mut entries = rows_at(doc, "/attackSurface/entryPoints")
        .filter_map(|row| entry_point_from_value(row, topology))
        .collect::<Vec<_>>();
    if entries.is_empty() {
        return empty_breakdown();
    }
    let target_count = entries
        .iter()
        .map(|entry| entry.targets.len() + entry.unresolved_target_count)
        .sum();
    let linked_target_count = entries.iter().map(|entry| entry.targets.len()).sum();
    let kinds = grouped_counts(entries.iter().map(|entry| entry.kind.as_str()));
    let zones = grouped_counts(entries.iter().map(|entry| entry.trust_zone.as_str()));
    sort_entries_by_zone(&mut entries, &zones);
    EntryPointBreakdown {
        kinds,
        zones,
        entries,
        linked_target_count,
        target_count,
        empty_hint: None,
    }
}

fn entry_point_from_value(
    value: &serde_json::Value,
    topology: &DfdModel,
) -> Option<EntryPointItem> {
    let target_ids = string_array(value, "targetElementIds");
    let targets = target_ids
        .iter()
        .filter_map(|target| {
            target_summary(topology, target).map(|label| EntryPointTarget {
                id: target.clone(),
                label,
            })
        })
        .collect::<Vec<_>>();
    Some(EntryPointItem {
        id: string_field(value, "id")?,
        name: first_string(value, &["name", "title", "handler", "route"])
            .unwrap_or_else(|| "unnamed entry point".to_string()),
        kind: string_field(value, "kind").unwrap_or_else(|| "uncategorized".to_string()),
        trust_zone: string_field(value, "trustZone").unwrap_or_else(|| "unknown".to_string()),
        description: string_field(value, "description").unwrap_or_default(),
        ingress: ingress_label(value),
        source: source_label(value),
        evidence: string_field(value, "evidence").unwrap_or_default(),
        unresolved_target_count: target_ids.len().saturating_sub(targets.len()),
        targets,
    })
}

fn sort_entries_by_zone(entries: &mut [EntryPointItem], zones: &[EntryPointGroup]) {
    entries.sort_by(|left, right| {
        zone_rank(zones, &left.trust_zone)
            .cmp(&zone_rank(zones, &right.trust_zone))
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.id.cmp(&right.id))
    });
}

fn zone_rank(zones: &[EntryPointGroup], zone: &str) -> usize {
    zones
        .iter()
        .position(|group| group.name == zone)
        .unwrap_or(zones.len())
}

fn target_summary(topology: &DfdModel, target_id: &str) -> Option<String> {
    if let Some(node) = topology.nodes.iter().find(|node| node.key == target_id) {
        return Some(format!("{target_id} {} · {}", node.name, node.zone));
    }
    if let Some(flow) = topology.flows.iter().find(|flow| flow.key == target_id) {
        return Some(format!("{target_id} {} → {}", flow.from, flow.to));
    }
    topology
        .boundaries
        .iter()
        .find(|boundary| boundary.key == target_id)
        .map(|boundary| format!("{target_id} {}", boundary.name))
}

fn ingress_label(value: &serde_json::Value) -> String {
    let method = string_field(value, "method");
    let route = string_field(value, "route");
    match (method, route) {
        (Some(method), Some(route)) => format!("{method} {route}"),
        (None, Some(route)) => route,
        (Some(method), None) => method,
        (None, None) => "not specified".to_string(),
    }
}

fn source_label(value: &serde_json::Value) -> String {
    let path = string_field(value, "path").unwrap_or_else(|| "not recorded".to_string());
    value
        .get("line")
        .and_then(serde_json::Value::as_u64)
        .map_or(path.clone(), |line| format!("{path}:{line}"))
}

fn first_string(value: &serde_json::Value, fields: &[&str]) -> Option<String> {
    fields.iter().find_map(|field| string_field(value, field))
}

fn grouped_counts<'a>(values: impl Iterator<Item = &'a str>) -> Vec<EntryPointGroup> {
    let mut counts = BTreeMap::<String, usize>::new();
    for value in values {
        *counts.entry(value.to_string()).or_default() += 1;
    }
    let mut groups = counts
        .into_iter()
        .map(|(name, count)| EntryPointGroup { name, count })
        .collect::<Vec<_>>();
    groups.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.name.cmp(&right.name))
    });
    groups
}

fn empty_breakdown() -> EntryPointBreakdown {
    EntryPointBreakdown {
        empty_hint: Some(
            "no entry points yet — run `threat-model:build` to discover ingress surfaces"
                .to_string(),
        ),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui_view_models::{DfdBoundaryModel, DfdKind, DfdNodeModel};
    use serde_json::json;

    #[test]
    fn breakdown_groups_all_entries_and_resolves_dfd_targets() {
        let doc = json!({
            "attackSurface": {"entryPoints": [
                {
                    "id": "EP-1", "name": "POST /admin", "kind": "http_route",
                    "method": "POST", "route": "/admin", "trustZone": "internet",
                    "path": "src/routes.rs", "line": 42, "description": "admin route",
                    "evidence": "src/routes.rs:42 route", "targetElementIds": ["N1", "TB1"]
                },
                {
                    "id": "EP-2", "name": "JSON.parse", "kind": "deserialization_point",
                    "trustZone": "internet", "path": "src/parser.rs",
                    "targetElementIds": ["missing"]
                }
            ]}
        });
        let topology = DfdModel {
            nodes: vec![DfdNodeModel {
                key: "N1".into(),
                name: "Admin API".into(),
                zone: "app".into(),
                kind: DfdKind::Process,
            }],
            boundaries: vec![DfdBoundaryModel {
                key: "TB1".into(),
                name: "Internet to app".into(),
                inner_zone: "app".into(),
                outer_zone: "internet".into(),
                crossing_flow_ids: Vec::new(),
            }],
            ..Default::default()
        };

        let model = entry_point_breakdown_from_doc(&doc, &topology);

        assert_eq!(model.entries.len(), 2);
        assert_eq!(model.linked_target_count, 2);
        assert_eq!(model.target_count, 3);
        assert_eq!(model.zones[0].name, "internet");
        assert_eq!(model.zones[0].count, 2);
        let admin = model
            .entries
            .iter()
            .find(|entry| entry.id == "EP-1")
            .expect("admin entry");
        assert_eq!(admin.ingress, "POST /admin");
        assert_eq!(admin.source, "src/routes.rs:42");
        assert_eq!(admin.targets[0].id, "N1");
        assert!(admin.targets[0].label.contains("Admin API"));
        let parser = model
            .entries
            .iter()
            .find(|entry| entry.id == "EP-2")
            .expect("parser entry");
        assert_eq!(parser.unresolved_target_count, 1);
    }
}
