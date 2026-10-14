use super::*;

pub(super) fn receipt(inventory: &RepositoryInventory) -> Value {
    let Some(inspection) = &inventory.inspection else {
        return json!({"status":"unknown","completeRepositoryCoverage":false});
    };
    let partial = inventory.truncation.is_some() || !inspection.truncated_files.is_empty();
    json!({
        "status": if partial { "partial" } else { "bounded" },
        "completeRepositoryCoverage":false,
        "enumeration":inspection.enumeration,
        "entries":inspection.entries,
        "inspectedBytes":inspection.inspected_bytes,
        "maxEntries":inspection.max_entries,
        "maxInspectedBytes":inspection.max_inspected_bytes,
        "maxFileInspectionBytes":inspection.max_file_inspection_bytes,
        "omittedPaths":inspection.omitted_paths.len(),
        "truncatedFiles":inspection.truncated_files.len(),
        "truncationReason":inventory.truncation.as_ref().map(|value| &value.reason),
    })
}

pub(super) fn output(summary: String, output: String, mut data: Value, coverage: Value) -> Value {
    let partial = coverage["status"] == "partial";
    data["inventoryCoverage"] = coverage.clone();
    data["findingsCoverage"] =
        json!({"sampling":"recent","limit":50,"completeLedgerCoverage":false});
    let output = format!("{output}\nInventory: {}. Full repository coverage is not established; inspect omitted and truncated counts.",coverage["status"].as_str().unwrap_or("unknown"));
    if partial {
        return crate::module_result::partial_output_result(
            summary,
            output,
            vec![json!(
                "Recommendations use partial inventory; omitted material was not reassessed"
            )],
            data,
        );
    }
    crate::module_result::completed_output_result(summary, output, data)
}
