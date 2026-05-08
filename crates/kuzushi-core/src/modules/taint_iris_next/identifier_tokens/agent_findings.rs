use super::*;

pub(in crate::modules::taint_iris_next) fn normalize_taint_iris_next_findings(
    items: Vec<Value>,
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
) -> Result<(Vec<Finding>, Vec<String>)> {
    let catalog_ids = plan
        .catalog
        .iter()
        .map(|entry| entry.cwe.clone())
        .collect::<BTreeSet<_>>();
    let mut findings = Vec::new();
    let mut warnings = Vec::new();
    for item in items {
        let Value::Object(object) = item else {
            continue;
        };
        let cwe = normalize_taint_next_cwe(
            &read_object_string(&object, &["cwe"]).unwrap_or_else(|| "CWE".to_string()),
        );
        if !catalog_ids.contains(&cwe)
            && read_object_string(&object, &["customCweRationale", "custom_cwe_rationale"])
                .is_none()
        {
            warnings.push(format!(
                "dropped finding with non-catalog CWE {cwe} and no customCweRationale"
            ));
            continue;
        }
        let title = read_object_string(&object, &["title"])
            .unwrap_or_else(|| format!("{} taint finding", cwe));
        let file_path = normalize_reported_file_path(
            read_object_string(&object, &["filePath", "file_path"])
                .unwrap_or_else(|| "unknown".to_string()),
            &plan.repo_root,
        );
        let start_line = read_object_u64(&object, &["startLine", "start_line"])
            .filter(|value| *value > 0)
            .unwrap_or(1) as u32;
        let evidence_level = read_object_string(&object, &["evidenceLevel", "evidence_level"])
            .unwrap_or_else(|| strongest_taint_iris_next_evidence_level(&cwe, evidence));
        if !taint_iris_next_evidence_meets_minimum(&evidence_level, &plan.caps.min_evidence_level) {
            warnings.push(format!(
                "dropped {cwe} finding below minEvidenceLevel={}; strongest evidence was {evidence_level}",
                plan.caps.min_evidence_level
            ));
            continue;
        }
        let detail = read_object_string(&object, &["message"]).unwrap_or_else(|| title.clone());
        let mut message = format!("[{cwe}] {title}: {detail}");
        if let Some(trace) = read_object_string(&object, &["sourceSinkTrace", "source_sink_trace"])
        {
            message.push_str("\nSource-to-sink trace: ");
            message.push_str(trace.trim());
        }
        let catalog_signals =
            read_object_string_array(&object, &["catalogSignals", "catalog_signals"]);
        if !catalog_signals.is_empty() {
            message.push_str("\nCatalog signals: ");
            message.push_str(&catalog_signals.join("; "));
        }
        if let Some(confidence) = read_object_string(&object, &["confidence"]) {
            message.push_str("\nConfidence: ");
            message.push_str(&confidence);
        }
        if let Some(path_summary) = summarize_taint_path(&object) {
            message.push_str("\nTaint path:\n");
            message.push_str(&path_summary);
        }
        findings.push(Finding::new_tool(
            "taint-iris-next",
            format!("taint-iris-next/{}", sanitize_rule_segment(&cwe)),
            file_path,
            start_line,
            None,
            agentic_severity(
                read_object_string(&object, &["severity"])
                    .as_deref()
                    .unwrap_or("medium"),
            ),
            message,
        ));
    }
    Ok((findings, warnings))
}
