use super::*;

pub(in crate::capabilities::taint_iris_next) fn normalize_taint_iris_next_findings(
    items: Vec<Value>,
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
) -> Result<(Vec<Finding>, Vec<String>)> {
    let catalog_ids = taint_next_catalog_ids(plan);
    let mut findings = Vec::new();
    let mut warnings = Vec::new();
    for item in items {
        if let Some(finding) =
            taint_next_finding_from_item(item, plan, evidence, &catalog_ids, &mut warnings)
        {
            findings.push(finding);
        }
    }
    Ok((findings, warnings))
}

fn taint_next_catalog_ids(plan: &TaintIrisNextPlan) -> BTreeSet<String> {
    plan.catalog
        .iter()
        .map(|entry| entry.cwe.clone())
        .collect()
}

fn taint_next_finding_from_item(
    item: Value,
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    catalog_ids: &BTreeSet<String>,
    warnings: &mut Vec<String>,
) -> Option<Finding> {
    let Value::Object(object) = item else {
        return None;
    };
    let cwe = taint_next_finding_cwe(&object, warnings);
    if !taint_next_catalog_allows(&object, &cwe, catalog_ids, warnings) {
        return None;
    }
    if !taint_next_evidence_allows(&object, &cwe, plan, evidence, warnings) {
        return None;
    }
    Some(build_taint_next_finding(&object, &cwe, plan, warnings))
}

fn taint_next_finding_cwe(object: &Map<String, Value>, warnings: &mut Vec<String>) -> String {
    match read_object_string(object, &["cwe"]) {
        Some(cwe) => normalize_taint_next_cwe(&cwe),
        None => {
            warnings.push("finding missing cwe; using CWE".to_string());
            normalize_taint_next_cwe("CWE")
        }
    }
}

fn taint_next_catalog_allows(
    object: &Map<String, Value>,
    cwe: &str,
    catalog_ids: &BTreeSet<String>,
    warnings: &mut Vec<String>,
) -> bool {
    if catalog_ids.contains(cwe)
        || read_object_string(object, &["customCweRationale", "custom_cwe_rationale"]).is_some()
    {
        return true;
    }
    warnings.push(format!(
        "dropped finding with non-catalog CWE {cwe} and no customCweRationale"
    ));
    false
}

fn taint_next_evidence_allows(
    object: &Map<String, Value>,
    cwe: &str,
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    warnings: &mut Vec<String>,
) -> bool {
    let evidence_level = read_object_string(object, &["evidenceLevel", "evidence_level"])
        .unwrap_or_else(|| strongest_taint_iris_next_evidence_level(cwe, evidence));
    let allowed =
        taint_iris_next_evidence_meets_minimum(&evidence_level, &plan.caps.min_evidence_level);
    if !allowed {
        warnings.push(format!(
            "dropped {cwe} finding below minEvidenceLevel={}; strongest evidence was {evidence_level}",
            plan.caps.min_evidence_level
        ));
    }
    allowed
}

fn build_taint_next_finding(
    object: &Map<String, Value>,
    cwe: &str,
    plan: &TaintIrisNextPlan,
    warnings: &mut Vec<String>,
) -> Finding {
    Finding::new_tool(
        "taint-iris-next",
        format!("taint-iris-next/{}", sanitize_rule_segment(cwe)),
        taint_next_file_path(object, plan),
        taint_next_start_line(object),
        None,
        taint_next_severity(object, cwe, warnings),
        taint_next_message(object, cwe),
    )
}

fn taint_next_file_path(object: &Map<String, Value>, plan: &TaintIrisNextPlan) -> String {
    normalize_reported_file_path(
        read_object_string(object, &["filePath", "file_path"])
            .unwrap_or_else(|| "unknown".to_string()),
        &plan.repo_root,
    )
}

fn taint_next_start_line(object: &Map<String, Value>) -> u32 {
    read_object_u64(object, &["startLine", "start_line"])
        .filter(|value| *value > 0)
        .unwrap_or(1) as u32
}

fn taint_next_message(object: &Map<String, Value>, cwe: &str) -> String {
    let title =
        read_object_string(object, &["title"]).unwrap_or_else(|| format!("{} taint finding", cwe));
    let detail = read_object_string(object, &["message"]).unwrap_or_else(|| title.clone());
    let mut message = format!("[{cwe}] {title}: {detail}");
    append_taint_next_message_extras(object, &mut message);
    message
}

fn append_taint_next_message_extras(object: &Map<String, Value>, message: &mut String) {
    append_optional_taint_next_text(
        message,
        "Source-to-sink trace",
        read_object_string(object, &["sourceSinkTrace", "source_sink_trace"]),
    );
    append_taint_next_catalog_signals(object, message);
    append_optional_taint_next_text(message, "Confidence", read_object_string(object, &["confidence"]));
    if let Some(path_summary) = summarize_taint_path(object) {
        message.push_str("\nTaint path:\n");
        message.push_str(&path_summary);
    }
}

fn append_optional_taint_next_text(message: &mut String, label: &str, value: Option<String>) {
    let Some(value) = value else {
        return;
    };
    message.push('\n');
    message.push_str(label);
    message.push_str(": ");
    message.push_str(value.trim());
}

fn append_taint_next_catalog_signals(object: &Map<String, Value>, message: &mut String) {
    let catalog_signals = read_object_string_array(object, &["catalogSignals", "catalog_signals"]);
    if catalog_signals.is_empty() {
        return;
    }
    message.push_str("\nCatalog signals: ");
    message.push_str(&catalog_signals.join("; "));
}

fn taint_next_severity(
    object: &Map<String, Value>,
    cwe: &str,
    warnings: &mut Vec<String>,
) -> Severity {
    match read_object_string(object, &["severity"]) {
        Some(label) => taint_next_labeled_severity(cwe, &label, warnings),
        None => {
            warnings.push(format!("finding {cwe} missing severity; using unknown"));
            Severity::Unknown
        }
    }
}

fn taint_next_labeled_severity(cwe: &str, label: &str, warnings: &mut Vec<String>) -> Severity {
    let severity = agentic_severity(label);
    if matches!(severity, Severity::Unknown) {
        warnings.push(format!(
            "finding {cwe} reported unrecognized severity `{label}`; using unknown"
        ));
    }
    severity
}
