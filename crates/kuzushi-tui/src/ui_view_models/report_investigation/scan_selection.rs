//! Present frozen requested settings separately from actual engine outcomes.
use kuzushi_core::workspace::InvestigationScanSelection;
use serde_json::{json, Value};
use std::collections::BTreeMap;

type SelectionGroups<'a> = BTreeMap<String, Vec<&'a InvestigationScanSelection>>;

pub(super) fn lines(selections: &[InvestigationScanSelection], details: bool) -> Vec<String> {
    if selections.is_empty() {
        return vec![
            "Planned scan settings: not recorded. Current settings are not substituted.".into(),
        ];
    }
    let groups = groups(selections);
    let mut lines = vec![overview_line(groups.len(), selections.len(), details)];
    for group in groups.values() {
        lines.extend(group_lines(group, details));
    }
    if details {
        lines.push("Requested settings alone do not establish enabled-rule coverage. Rule-source contents are not pinned by this receipt.".into());
    }
    lines
}

pub(super) fn insert(lines: &mut Vec<String>, settings: Vec<String>) {
    let position = lines
        .iter()
        .position(|line| line.starts_with("Model: "))
        .or_else(|| lines.iter().position(|line| line.starts_with("Coverage: ")))
        .map_or(lines.len(), |position| position + 1);
    lines.splice(position..position, settings);
}

fn overview_line(choices: usize, cases: usize, details: bool) -> String {
    let action = if details { "p overview" } else { "p details" };
    let selections = quantity(choices, "selection", "selections");
    if cases == 1 {
        return format!("Planned scan settings: {selections} recorded · {action}");
    }
    format!("Planned scan settings: {selections} across {cases} plan cases · {action}")
}

fn quantity(count: usize, singular: &str, plural: &str) -> String {
    let noun = if count == 1 { singular } else { plural };
    format!("{count} {noun}")
}

fn groups(selections: &[InvestigationScanSelection]) -> SelectionGroups<'_> {
    let mut groups: SelectionGroups<'_> = BTreeMap::new();
    for selection in selections {
        groups
            .entry(json!(&selection.parameters).to_string())
            .or_default()
            .push(selection);
    }
    groups
}

fn group_lines(group: &[&InvestigationScanSelection], details: bool) -> Vec<String> {
    let Some(first) = group.first() else {
        return Vec::new();
    };
    let tasks = first
        .parameters
        .get("tasks")
        .map(Value::to_string)
        .unwrap_or_else(|| "not recorded".into());
    let mut lines = vec![format!(
        "Requested tasks: {tasks} · Semgrep sources: {} · {}",
        source_summary(first.parameters.get("semgrepConfig")),
        quantity(group.len(), "plan case", "plan cases")
    )];
    if details {
        let cases: Vec<_> = group
            .iter()
            .filter_map(|selection| selection.case_id.as_deref())
            .collect();
        if !cases.is_empty() {
            lines.push(format!("Plan case ids: {}", json!(cases)));
        }
        lines.extend(
            first
                .parameters
                .iter()
                .map(|(key, value)| format!("  {key}: {value}")),
        );
    }
    lines
}

fn source_summary(value: Option<&Value>) -> String {
    match value {
        None => "not recorded".into(),
        Some(Value::Array(sources)) => source_count(sources),
        Some(_) => "non-list request; coverage unknown".into(),
    }
}

fn source_count(sources: &[Value]) -> String {
    if sources.is_empty() {
        return "empty request; coverage unknown".into();
    }
    if !sources.iter().all(Value::is_string) {
        return "invalid source list; coverage unknown".into();
    }
    format!("{} requested", sources.len())
}

#[cfg(test)]
mod tests;
