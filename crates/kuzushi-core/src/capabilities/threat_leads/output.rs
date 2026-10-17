use serde_json::{json, Value};
use std::path::Path;

pub(super) fn tool_output(target: &Path, report: Value) -> Value {
    let count = report["leadCount"].as_u64().unwrap_or_default();
    let artifact = super::threat_leads_artifact_path(target);
    let summary_artifact = super::threat_leads_summary_path(target);
    let status = report["sourceCoverage"]["status"]
        .as_str()
        .unwrap_or("legacy-unverified");
    let publication = super::publication::inspect_summary(target, &report);
    let summary = format!(
        "{status} source inspection · {} threat lead{}",
        count,
        if count == 1 { "" } else { "s" },
    );
    let output = format!(
        "{summary}\n  Artifact: {}\n{}\n{}",
        artifact.display(),
        publication.message(),
        coverage_lines(&report).join("\n")
    );
    let mut result = report_result(summary, output, report, publication);
    let paths = [
        ("threat-leads", artifact),
        ("threat-leads-summary", summary_artifact),
    ];
    result["summaryPublication"] = json!({"status":publication.label(),"jsonAuthoritative":true});
    result["artifacts"] = json!(paths
        .into_iter()
        .filter(|(label, _)| *label != "threat-leads-summary"
            || publication == super::publication::SummaryState::Current)
        .filter_map(|(label, path)| {
            std::fs::symlink_metadata(&path)
                .ok()
                .filter(|metadata| metadata.is_file())
                .map(|_| json!({"label":label,"path":path.display().to_string()}))
        })
        .collect::<Vec<_>>());
    result
}

fn report_result(
    summary: String,
    output: String,
    report: Value,
    publication: super::publication::SummaryState,
) -> Value {
    if report["sourceCoverage"]["status"] == "bounded"
        && publication == super::publication::SummaryState::Current
    {
        return crate::module_result::completed_output_result(summary, output, report);
    }
    crate::module_result::partial_output_result(summary, output,
        vec![json!("Inspection or summary publication is partial or unverified. These cards are context hints; accepted Map and finding verdicts are unchanged.")], report)
}

pub(super) fn coverage_lines(report: &Value) -> Vec<String> {
    let coverage = &report["sourceCoverage"];
    let status = coverage["status"].as_str().unwrap_or("legacy-unverified");
    let mut lines = vec![
        format!("Source inspection: {status}. Complete repository coverage is not established."),
        "Experimental keyword hints. No accepted Map, scan jobs or findings were created.".into(),
        format!("Indexed files: {} · known source read: {} · omitted source files: {} · prefix-limited files: {}",
            count(&coverage["indexedFiles"]),byte_count(&coverage["inspectedSourceBytes"]),
            count(&coverage["omittedSourceFiles"]),count(&coverage["truncatedSourceFiles"])),
        format!("Inventory entries: {} · inventory omitted paths: {} · inventory prefix-limited files: {}",
            count(&coverage["inventory"]["entries"]),count(&coverage["inventory"]["omittedPaths"]),count(&coverage["inventory"]["truncatedFiles"])),
        "Confidence records keyword overlap; vulnerability validity and current source equivalence are not established.".into(),
    ];
    lines.push(format!(
        "Threat-model receipt: {}",
        report["sources"]["threatModelSha256"]
            .as_str()
            .unwrap_or("unrecorded")
    ));
    lines.extend(projection_lines(&coverage["contextProjection"]));
    lines.extend(resource_lines(coverage));
    append_omissions(&mut lines, coverage);
    append_inventory_paths(&mut lines, coverage);
    lines
}

fn projection_lines(projection: &Value) -> Vec<String> {
    vec![
        format!("Context limits: {} DFD rows per kind · {} references per field · {} text prefixes",
            count(&projection["maxDfdRowsPerKind"]), count(&projection["maxReferencesPerField"]), byte_count(&projection["maxTextFieldBytes"])),
        format!("Context omissions: {} DFD rows · {} duplicate element IDs · {} values · {} shortened field projections · {} cards",
            count(&projection["omittedElements"]),count(&projection["duplicateElementIds"]),count(&projection["omittedValues"]),count(&projection["truncatedTextFields"]),count(&projection["omittedLeadCards"])),
        format!("Retained card bytes: {} of {} · duplicate references removed: {}",
            byte_count(&projection["retainedCardBytes"]),byte_count(&projection["maxRetainedCardBytes"]),count(&projection["duplicateReferences"])),
    ]
}

fn resource_lines(coverage: &Value) -> Vec<String> {
    vec![
        format!(
            "Index bounds: {} file attempts · {} per file · {} source maximum",
            count(&coverage["maxSourceFiles"]),
            byte_count(&coverage["maxFileBytes"]),
            byte_count(&coverage["maxSourceBytes"])
        ),
        format!(
            "Combined inventory/source ceiling: {} · reserved source reads: {}",
            byte_count(&coverage["maxCombinedInspectedBytes"]),
            byte_count(&coverage["reservedSourceBytes"])
        ),
    ]
}

fn count(value: &Value) -> String {
    value
        .as_u64()
        .map(|n| n.to_string())
        .unwrap_or_else(|| "unrecorded".into())
}

fn byte_count(value: &Value) -> String {
    let Some(bytes) = value.as_u64() else {
        return "unrecorded".into();
    };
    let units = [("MiB", 1024 * 1024), ("KiB", 1024)];
    match units.into_iter().find(|(_, scale)| bytes >= *scale) {
        Some((unit, scale)) => format!("{:.1} {unit}", bytes as f64 / scale as f64),
        None => format!("{bytes} B"),
    }
}

fn append_omissions(lines: &mut Vec<String>, coverage: &Value) {
    for row in coverage["omissions"]
        .as_array()
        .into_iter()
        .flatten()
        .take(8)
    {
        lines.push(format!(
            "Omitted {}: {}",
            row["path"].as_str().unwrap_or("unrecorded"),
            row["reason"].as_str().unwrap_or("unrecorded")
        ));
    }
    if coverage["omittedSourceFiles"].as_u64().unwrap_or(0) > 8 {
        lines.push("Additional omissions are recorded in the JSON artifact; path previews are bounded to 128 entries.".into());
    }
}

fn append_inventory_paths(lines: &mut Vec<String>, coverage: &Value) {
    for path in coverage["truncatedPaths"]
        .as_array()
        .into_iter()
        .flatten()
        .take(8)
    {
        lines.push(format!(
            "Prefix-limited source: {}",
            path.as_str().unwrap_or("unrecorded")
        ));
    }
    for row in coverage["inventory"]["omissions"]
        .as_array()
        .into_iter()
        .flatten()
        .take(8)
    {
        lines.push(format!(
            "Inventory omitted {}: {}",
            row["path"].as_str().unwrap_or("unrecorded"),
            row["reason"].as_str().unwrap_or("unrecorded")
        ));
    }
}

pub(super) fn append_publication_warning(result: &mut Value, warning: Option<String>) {
    let Some(warning) = warning else {
        return;
    };
    result["status"] = json!("partial");
    if let Some(warnings) = result["warnings"].as_array_mut() {
        warnings.push(json!(warning));
    }
    if let Some(text) = result["output"].as_str() {
        result["output"] = json!(format!("{text}\n{warning}"));
    }
}
