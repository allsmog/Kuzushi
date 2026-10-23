//! Keep selected excerpt completeness separate from repository enumeration.
use serde_json::Value;

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
}
