//! Read recorded source-input receipts without treating them as independent proof.
use serde_json::Value;

mod details;
#[cfg(test)]
mod tests;

pub(super) fn receipt_lines(document: &Value) -> Vec<String> {
    let mut lines = provenance_lines(&document["provenance"]);
    if !lines.is_empty() {
        lines.push("Tab reads the complete document, including frozen excerpts and the generation receipt.".into());
    }
    lines
}

pub(super) fn provenance_lines(provenance: &Value) -> Vec<String> {
    [
        ("scopeContext", "FILE-GROUP CONTEXT RECEIPT"),
        ("fileContext", "EVIDENCE CONTEXT RECEIPT"),
    ]
    .into_iter()
    .flat_map(|(key, title)| wrapper_lines(&provenance[key], title))
    .collect()
}

fn wrapper_lines(wrapper: &Value, title: &str) -> Vec<String> {
    if wrapper.is_null() {
        return Vec::new();
    }
    let mut lines = vec![String::new(), title.into()];
    let Some(receipt) = valid_receipt(wrapper) else {
        lines.push(
            "Source-input receipt unavailable: unsupported or malformed recorded evidence.".into(),
        );
        return lines;
    };
    lines.extend(recorded_lines(receipt));
    lines
}

fn valid_receipt(wrapper: &Value) -> Option<&Value> {
    if wrapper["status"] == "unavailable" {
        return None;
    }
    let receipt = wrapper.get("receipt")?;
    if receipt["schemaVersion"] != 1 {
        return None;
    }
    let files = receipt.pointer("/sourceEvidence/files")?.as_array()?;
    files.iter().all(valid_file).then_some(receipt)
}

fn valid_file(file: &Value) -> bool {
    let Some(path) = file["path"].as_str() else {
        return false;
    };
    let Some(lines) = file["lines"].as_array() else {
        return false;
    };
    !path.is_empty() && lines.iter().all(|line| line["ref"].is_string())
}

fn recorded_lines(receipt: &Value) -> Vec<String> {
    let mut lines = vec![
        selection_line(receipt),
        format!(
            "Selected source partial: {} · complete repository coverage: {}",
            flag(&receipt["sourcePartial"]),
            flag(&receipt["completeRepositoryCoverage"])
        ),
        "These are recorded inputs, not independent proof of coverage or model quality.".into(),
    ];
    lines.extend(details::lines(receipt));
    lines.extend(super::super::evidence_inventory::receipt_lines(
        receipt.get("inventory"),
    ));
    lines
}

fn selection_line(receipt: &Value) -> String {
    let source = &receipt["sourceEvidence"];
    let (label, value) = match receipt.get("selectedFileCount") {
        Some(value) => ("Requested files", value),
        None => ("Eligible source files", &source["eligibleFiles"]),
    };
    format!(
        "{label}: {} · supplied excerpts: {}",
        count(value),
        source["files"].as_array().map_or(0, Vec::len)
    )
}

fn count(value: &Value) -> String {
    value
        .as_u64()
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unrecorded".into())
}

fn flag(value: &Value) -> &'static str {
    match value.as_bool() {
        Some(true) => "true",
        Some(false) => "false",
        None => "unrecorded",
    }
}
