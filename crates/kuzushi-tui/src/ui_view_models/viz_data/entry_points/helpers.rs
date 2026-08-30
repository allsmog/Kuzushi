use super::model::{EntryPointGroup, EntryPointTarget, SOURCE_NOT_RECORDED};
use crate::ui_view_models::viz_data::dfd::{string_field, DfdModel};
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) const NOT_MODELED_ZONE: &str = "not modeled";

pub(super) fn entry_name(value: &Value) -> String {
    first_string(value, &["name", "title", "handler", "route"])
        .unwrap_or_else(|| "unnamed entry point".to_string())
}

pub(super) fn nonempty_string_field(value: &Value, field: &str) -> Option<String> {
    string_field(value, field).filter(|text| !text.trim().is_empty())
}

pub(super) fn resolved_targets(
    topology: &DfdModel,
    target_ids: &[String],
) -> Vec<EntryPointTarget> {
    target_ids
        .iter()
        .filter_map(|target| {
            target_summary(topology, target).map(|label| EntryPointTarget {
                id: target.clone(),
                label,
            })
        })
        .collect()
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

pub(super) fn ingress_label(value: &Value) -> String {
    let method = string_field(value, "method");
    let route = string_field(value, "route");
    match (method, route) {
        (Some(method), Some(route)) => format!("{method} {route}"),
        (None, Some(route)) => route,
        (Some(method), None) => method,
        (None, None) => "not specified".to_string(),
    }
}

pub(super) fn source_label(value: &Value) -> String {
    let path = string_field(value, "path")
        .or_else(|| string_field(value, "location"))
        .unwrap_or_else(|| SOURCE_NOT_RECORDED.to_string());
    value
        .get("line")
        .and_then(Value::as_u64)
        .filter(|_| !path.contains(':'))
        .map_or(path.clone(), |line| format!("{path}:{line}"))
}

pub(super) fn risk_label(value: &Value) -> String {
    let Some(risk) = value.get("risk") else {
        return String::new();
    };
    if let Some(label) = risk.as_str() {
        return label.to_string();
    }
    let mut parts = Vec::new();
    push_risk_string(&mut parts, risk, "tier");
    push_risk_number(&mut parts, risk, "score");
    push_risk_number(&mut parts, risk, "rank");
    parts.join(" · ")
}

fn push_risk_string(parts: &mut Vec<String>, risk: &Value, field: &str) {
    if let Some(value) = string_field(risk, field) {
        parts.push(value);
    }
}

fn push_risk_number(parts: &mut Vec<String>, risk: &Value, field: &str) {
    if let Some(value) = risk.get(field).and_then(Value::as_u64) {
        parts.push(format!("{field} {value}"));
    }
}

pub(super) fn first_string(value: &Value, fields: &[&str]) -> Option<String> {
    fields.iter().find_map(|field| string_field(value, field))
}

pub(super) fn grouped_counts<'a>(values: impl Iterator<Item = &'a str>) -> Vec<EntryPointGroup> {
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
