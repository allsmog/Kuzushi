//! Keep selected excerpt completeness separate from repository enumeration.
use serde_json::Value;

pub(super) fn filename_receipt_lines(inventory: Option<&Value>) -> Vec<String> {
    let Some(inventory) = inventory else {
        return Vec::new();
    };
    if inventory["schemaVersion"] != 1
        || !filename_counts_match(inventory)
        || inventory["completeRepositoryCoverage"] != false
    {
        return vec!["Repository filename receipt unavailable: unsupported or inconsistent recorded limits. Inspect the saved context.".into()];
    }
    let mut lines = vec![
        String::new(),
        "BASE SYNTHESIS FILENAME INVENTORY".into(),
        format!(
            "Filename list: {} of {} enumerated paths; {} not listed here.",
            count(&inventory["listedFiles"]),
            count(&inventory["enumeratedFiles"]),
            count(&inventory["unlistedFiles"])
        ),
    ];
    lines.extend(receipt_lines(Some(inventory)));
    if let Some(policy) = inventory["membershipPolicy"].as_str() {
        lines.push(format!("Membership policy: {policy}"));
    }
    lines.extend(filename_examples(inventory));
    lines.push("Other source sections have separate limits. A listed filename does not establish inspected code or complete coverage.".into());
    lines
}

fn filename_examples(inventory: &Value) -> Vec<String> {
    let mut lines = Vec::new();
    for (key, label) in [
        ("omittedPathExamples", "Omitted path"),
        ("truncatedFileExamples", "Partial content"),
    ] {
        for row in inventory[key].as_array().into_iter().flatten().take(20) {
            let value = row.get("path").unwrap_or(row);
            lines.push(format!("{label}: {value}"));
        }
    }
    lines
}

fn filename_counts_match(inventory: &Value) -> bool {
    let Some(paths) = inventory["listedPaths"].as_array() else {
        return false;
    };
    if inventory["listedFiles"].as_u64() != u64::try_from(paths.len()).ok()
        || !paths.iter().all(Value::is_string)
    {
        return false;
    }
    inventory["listedFiles"]
        .as_u64()
        .zip(inventory["unlistedFiles"].as_u64())
        .and_then(|(listed, unlisted)| listed.checked_add(unlisted))
        .zip(inventory["enumeratedFiles"].as_u64())
        .is_some_and(|(sum, enumerated)| sum == enumerated)
}

pub(super) fn receipt_lines(inventory: Option<&Value>) -> Vec<String> {
    let Some(inventory) = inventory else {
        return vec!["Repository inventory extent: not recorded for this context.".into()];
    };
    let extent = enumeration_extent(inventory);
    let membership = membership_label(inventory);
    let mut lines = vec![format!("Repository enumeration: {extent}; {membership}."),
        format!("Enumerated files: {} · omitted paths: {} · partial inspections: {}", count(&inventory["enumeratedFiles"]), count(&inventory["omittedPathCount"]), count(&inventory["truncatedFileCount"])),
        format!("Inventory limit: {} entries · {} total · {} per file", count(&inventory["maxEntries"]), byte_limit(&inventory["maxInspectedBytes"]), byte_limit(&inventory["maxFileInspectionBytes"])),
        "Enumeration extent and selected-source excerpts are separate. Complete repository coverage is not claimed.".into()];
    if let Some(reason) = inventory
        .pointer("/truncation/reason")
        .and_then(Value::as_str)
    {
        lines.push(format!("Inventory limitation: {reason}"));
    }
    lines
}

fn enumeration_extent(inventory: &Value) -> &'static str {
    match inventory["enumerationComplete"].as_bool() {
        Some(true) => "complete under inventory policy",
        Some(false) => "partial",
        None => "unknown",
    }
}

fn membership_label(inventory: &Value) -> &'static str {
    if inventory["selectionKind"] == "filename-list" && inventory["selectedMembershipKnown"] == true
    {
        return "listed filename membership is recorded";
    }
    if inventory["selectedMembershipKnown"] == true {
        "all selected files are recorded"
    } else {
        "selected membership is unverified"
    }
}

fn count(value: &Value) -> String {
    value
        .as_u64()
        .map(|number| number.to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn byte_limit(value: &Value) -> String {
    let Some(bytes) = value.as_u64() else {
        return "unknown".into();
    };
    let unit = [(1024 * 1024, "MiB"), (1024, "KiB")]
        .into_iter()
        .find(|(scale, _)| bytes >= *scale && bytes.is_multiple_of(*scale));
    unit.map_or_else(
        || format!("{bytes} B"),
        |(scale, unit)| format!("{} {unit}", bytes / scale),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn partial_inventory_can_have_exact_selected_membership() {
        let receipt = json!({"enumerationComplete":false,"selectedMembershipKnown":true,"enumeratedFiles":99998,
            "omittedPathCount":2,"truncatedFileCount":0,"maxEntries":100000,"maxInspectedBytes":536870912,"maxFileInspectionBytes":262144,
            "truncation":{"reason":"entry cap reached"}});
        let text = receipt_lines(Some(&receipt)).join("\n");
        assert!(text.contains("Repository enumeration: partial; all selected files are recorded"));
        assert!(text.contains("99998") && text.contains("omitted paths: 2"));
        assert!(text.contains("512 MiB total · 256 KiB per file"));
        assert!(text.contains("entry cap reached") && text.contains("coverage is not claimed"));
    }

    #[test]
    fn missing_extent_and_membership_remain_unknown() {
        let text = receipt_lines(Some(&json!({}))).join("\n");
        assert!(text.contains("unknown; selected membership is unverified"));
        assert!(text.contains("Enumerated files: unknown") && !text.contains("null"));
        assert!(receipt_lines(None).join("\n").contains("not recorded"));
    }

    #[test]
    fn byte_limits_remain_exact_without_rounding_or_unknown_zeroes() {
        for (value, expected) in [
            (json!(null), "unknown"),
            (json!(0), "0 B"),
            (json!(1499), "1499 B"),
            (json!(1024), "1 KiB"),
            (json!(536870912), "512 MiB"),
        ] {
            assert_eq!(byte_limit(&value), expected);
        }
    }
    fn filename_inventory() -> Value {
        json!({"schemaVersion":1,"selectionKind":"filename-list","selectedMembershipKnown":true,
            "listedPaths":["owned.rs","second.rs"],"listedFiles":2,"enumeratedFiles":5,"unlistedFiles":3,"enumerationComplete":false,
            "omittedPathCount":4,"truncatedFileCount":1,"maxEntries":100000,
            "maxInspectedBytes":536870912,"maxFileInspectionBytes":262144,
            "truncation":{"reason":"Owned enumeration cap"},"completeRepositoryCoverage":false})
    }

    #[test]
    fn filename_receipt_keeps_listing_and_content_inspection_separate() {
        let text = filename_receipt_lines(Some(&filename_inventory())).join("\n");
        assert!(text.contains("Filename list: 2 of 5 enumerated paths; 3 not listed here."));
        assert!(text.contains("enumeration: partial; listed filename membership is recorded"));
        assert!(text.contains("partial inspections: 1"));
        assert!(text.contains("Owned enumeration cap"));
        assert!(text.contains("512 MiB") && text.contains("256 KiB"));
        assert!(text.contains("A listed filename does not establish inspected code"));
    }

    #[test]
    fn inconsistent_or_unsupported_filename_receipts_do_not_report_zero_or_complete_coverage() {
        for (key, value) in [
            ("schemaVersion", json!(2)),
            ("listedFiles", json!(9)),
            ("enumeratedFiles", Value::Null),
            ("completeRepositoryCoverage", json!(true)),
        ] {
            let mut receipt = filename_inventory();
            receipt[key] = value;
            let text = filename_receipt_lines(Some(&receipt)).join("\n");
            assert!(text.contains("receipt unavailable"), "{text}");
            assert!(!text.contains("Filename list: 0"), "{text}");
        }
        assert!(filename_receipt_lines(None).is_empty());
    }

    #[test]
    fn filename_receipt_does_not_conflate_complete_enumeration_with_full_content() {
        let mut receipt = filename_inventory();
        receipt["enumerationComplete"] = json!(true);
        let text = filename_receipt_lines(Some(&receipt)).join("\n");
        assert!(text.contains("enumeration: complete under inventory policy"));
        assert!(text.contains("partial inspections: 1"));
        assert!(text.contains("Complete repository coverage is not claimed"));
    }
}
