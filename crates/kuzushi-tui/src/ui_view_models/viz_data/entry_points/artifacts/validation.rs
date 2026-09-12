use super::super::model::EntryPointCounts;
use super::fields::{pointer_usize, ReceiptFields};
use serde_json::Value;

/// A catalog the context snapshot could only partly supply says so in its own
/// artifact. The page repeats that, so its rows never read as the whole
/// attack surface. An artifact written before coverage was recorded omits the
/// field; those could only be built from a complete snapshot.
pub(super) fn warn_unless_coverage_is_complete(
    catalog: Option<&Value>,
    warnings: &mut Vec<String>,
) {
    let Some(coverage) = catalog.and_then(|doc| doc.get("snapshotCoverage")) else {
        return;
    };
    match coverage.get("state").and_then(Value::as_str) {
        Some("complete") => {}
        Some("partial") => warnings.push(partial_coverage_warning(coverage)),
        _ => warnings.push("catalog declares an unreadable coverage state".to_string()),
    }
}

fn partial_coverage_warning(coverage: &Value) -> String {
    let reason = coverage
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("unstated reason");
    let mut warning = format!("catalog coverage partial: context snapshot truncated ({reason})");
    if let Some(omitted) = coverage.get("omittedEntries").and_then(Value::as_u64) {
        warning.push_str(&format!("; {omitted} snapshot entries omitted"));
    }
    warning
}

pub(super) fn validate_receipt_counts(
    catalog: Option<&Value>,
    fields: &ReceiptFields,
    counts: &EntryPointCounts,
    warnings: &mut Vec<String>,
) {
    validate_artifact_counts(catalog, fields, counts, warnings);
    validate_count_relations(fields, warnings);
}

fn validate_artifact_counts(
    catalog: Option<&Value>,
    fields: &ReceiptFields,
    counts: &EntryPointCounts,
    warnings: &mut Vec<String>,
) {
    push_count_mismatch(
        "catalog total",
        pointer_usize(catalog, "/total"),
        counts.extracted,
        warnings,
    );
    push_count_mismatch(
        "catalog receipt records",
        fields.records,
        counts.extracted,
        warnings,
    );
    push_count_mismatch(
        "catalog linked coverage",
        fields.records_linked,
        counts.overlap,
        warnings,
    );
}

fn validate_count_relations(fields: &ReceiptFields, warnings: &mut Vec<String>) {
    push_invalid_relation(
        "selected",
        fields.records_selected,
        "records",
        fields.records,
        warnings,
    );
    push_invalid_relation(
        "linked",
        fields.records_linked,
        "records",
        fields.records,
        warnings,
    );
    push_invalid_relation(
        "modeled",
        fields.records_selected,
        "grounding-selected",
        fields.grounding_records_selected,
        warnings,
    );
    push_invalid_relation(
        "grounding-selected",
        fields.grounding_records_selected,
        "grounding limit",
        fields.grounding_limit,
        warnings,
    );
}

fn push_count_mismatch(
    label: &str,
    declared: Option<usize>,
    actual: usize,
    warnings: &mut Vec<String>,
) {
    if let Some(declared) = declared.filter(|declared| *declared != actual) {
        warnings.push(format!(
            "{label} {declared} does not match {actual} valid stable-id row(s)"
        ));
    }
}

fn push_invalid_relation(
    child_label: &str,
    child: Option<usize>,
    parent_label: &str,
    parent: Option<usize>,
    warnings: &mut Vec<String>,
) {
    if child
        .zip(parent)
        .is_some_and(|(child, parent)| child > parent)
    {
        warnings.push(format!(
            "catalog receipt invalid: {child_label} exceeds {parent_label}"
        ));
    }
}
