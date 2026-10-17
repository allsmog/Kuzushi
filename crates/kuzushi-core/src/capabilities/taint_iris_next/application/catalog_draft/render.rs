use super::*;

pub(super) fn failed(message: &str) -> Value {
    crate::module_result::failed_output_result(
        "Catalog draft failed",
        message,
        json!({"status":"draft-failed","priorCatalogPreserved":true,"parseError":message}),
    )
}

pub(super) fn unreadable(reference: &str, error: &anyhow::Error) -> Value {
    crate::module_result::failed_output_result("Saved taint catalog is unreadable",
        format!("{error:#}\nExact raw catalog digest: {reference}\nThe bytes were preserved. To replace them with an already reviewed draft, explicitly confirm expectedActiveDigest={reference}. No model request or scan is required."),
        json!({"status":"unreadable","catalogDigestRef":reference,"sourceFreshnessVerified":false,"priorCatalogPreserved":true}))
}

pub(super) fn draft(draft: &CatalogDraft, reference: &str) -> Result<Value> {
    let lines = draft_lines(draft, reference);
    let data = draft_data(draft, reference);
    let summary = format!(
        "Taint catalog draft: {}; {} context",
        entries_count(draft.catalog.len()),
        draft.inspection["status"].as_str().unwrap_or("unavailable")
    );
    if draft.inspection["status"] == "partial" {
        return Ok(crate::module_result::partial_output_result(
            summary,
            lines.join("\n"),
            vec![json!(
                "Partial context must be reviewed and acknowledged before acceptance"
            )],
            data,
        ));
    }
    Ok(crate::module_result::completed_output_result(
        summary,
        lines.join("\n"),
        data,
    ))
}

fn draft_lines(draft: &CatalogDraft, reference: &str) -> Vec<String> {
    let mut lines = vec![
        format!(
            "TAINT CATALOG DRAFT · {}",
            entries_count(draft.catalog.len())
        ),
        "Review before acceptance. This draft changes no active catalog and starts no scan.".into(),
        format!(
            "Context coverage: {}. Complete repository coverage is not established.",
            draft.inspection["status"].as_str().unwrap_or("unavailable")
        ),
        "Priority scores guide review; they do not establish vulnerabilities.".into(),
    ];
    for entry in &draft.catalog {
        append_entry(&mut lines, entry);
    }
    lines.extend(inspection_lines(draft));
    lines.extend([format!("Active catalog at draft creation: {}", draft.base_catalog_digest.as_deref().unwrap_or("absent")),
        format!("Draft reference: {reference}"),
        "Next: review with taint-iris-next:catalog-read, then explicitly accept with taint-iris-next:catalog-accept.".into(),
        "Acceptance requires unchanged source and active catalog. Partial context needs explicit acknowledgement.".into(),
        "Historical reading does not verify current source freshness.".into()]);
    lines
}

fn inspection_lines(draft: &CatalogDraft) -> Vec<String> {
    vec![
        "INPUTS AND LIMITS".into(),
        format!(
            "Prompt source: {}. Omitted from prompt: {}. Truncated prompt files: {}.",
            files_count(&draft.inspection["promptSourceFiles"]),
            files_count(&draft.inspection["promptOmittedFiles"]),
            draft.inspection["promptTruncatedSourceFiles"]
        ),
        format!(
            "Truncated inspected source prefixes: {}.",
            draft.inspection["truncatedSourceFiles"]
        ),
        format!(
            "Source limits: {}, {} bytes, {} bytes/file.",
            files_count(&draft.inspection["maxSourceFiles"]),
            draft.inspection["maxSourceBytes"],
            draft.inspection["maxFileBytes"]
        ),
        format!(
            "Model: {}. One model turn; no tools or automatic repair.",
            draft.model
        ),
        format!("Inspected source tree: {}", draft.source_tree_hash),
    ]
}

pub(super) fn entries_count(count: usize) -> String {
    let noun = if count == 1 { "entry" } else { "entries" };
    format!("{count} {noun}")
}

fn files_count(value: &Value) -> String {
    let Some(count) = value.as_u64() else {
        return "unknown file count".into();
    };
    let noun = if count == 1 { "file" } else { "files" };
    format!("{count} {noun}")
}

fn draft_data(draft: &CatalogDraft, reference: &str) -> Value {
    let data = json!({"target":draft.target,"status":"draft","catalogPath":null,"draftRef":reference,
        "entries":draft.catalog,"model":draft.model,"sourceTreeHash":draft.source_tree_hash,
        "inspection":draft.inspection,"sourceFreshnessVerified":false,"activeCatalogChanged":false,"baseCatalogDigestRef":draft.base_catalog_digest});
    data
}

pub(super) fn inputs(draft: &CatalogDraft, reference: &str) -> Result<Value> {
    let mut lines = vec![
        "FROZEN CATALOG INPUTS".into(),
        "Historical source/context supplied to this draft. Current source freshness is unverified."
            .into(),
    ];
    if let Some(sources) = draft.frozen_input["sources"].as_array() {
        for source in sources {
            lines.push(format!(
                "Source: {}",
                source["path"].as_str().unwrap_or("unavailable")
            ));
            lines.push(source["text"].as_str().unwrap_or("unavailable").into());
        }
    }
    for field in ["context", "threatModel"] {
        lines.push(format!("{field}: {}", draft.inspection[field]));
        lines.push(
            draft.frozen_input[field]
                .as_str()
                .unwrap_or("explicitly absent")
                .into(),
        );
    }
    lines.extend(["System prompt:".into(), draft.system_prompt.clone()]);
    Ok(crate::module_result::completed_output_result(
        "Frozen catalog inputs",
        lines.join("\n"),
        json!({"draftRef":reference,"frozenInput":draft.frozen_input,"systemPrompt":draft.system_prompt,"inspection":draft.inspection,"sourceFreshnessVerified":false}),
    ))
}

fn append_entry(lines: &mut Vec<String>, entry: &Value) {
    lines.push(format!(
        "{} · {} · priority {}",
        entry["cwe"].as_str().unwrap_or("unavailable"),
        entry["name"].as_str().unwrap_or("unavailable"),
        entry["score"]
    ));
    for (field, label) in [
        ("sourceSignals", "Sources"),
        ("sinkSignals", "Sinks"),
        ("sanitizerSignals", "Sanitizers"),
        ("structuralQueries", "Structure queries"),
        ("reasons", "Why"),
    ] {
        let values = entry[field]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("; ")
            })
            .unwrap_or_default();
        if !values.is_empty() {
            lines.push(format!("  {label}: {values}"));
        }
    }
}

pub(super) fn profile(value: &Value, reference: &str) -> Result<Value> {
    let text = serde_json::to_string(value)?;
    let entries = super::super::dynamic_catalog::parse_target_catalog_payload(&text)?;
    let mut lines = vec![format!("SAVED TAINT CATALOG · {}", entries_count(entries.len())),
        "Historical configuration. Current source freshness is unverified.".into(),
        format!("Exact catalogDigestRef: {reference}"),
        "Pin this reference in a separately approved scan plan. Reading starts no scan or model request.".into()];
    for entry in &entries {
        append_entry(&mut lines, &serde_json::to_value(entry)?);
    }
    let legacy = value.get("acceptedDraftRef").is_none();
    if legacy {
        lines.push("Legacy configuration has no frozen model-input or acceptance history.".into());
    }
    Ok(crate::module_result::completed_output_result(
        "Saved taint catalog",
        lines.join("\n"),
        json!({"status":"saved","catalogDigestRef":reference,"entries":entries,"acceptedDraftRef":value["acceptedDraftRef"],"sourceFreshnessVerified":false,"legacyUnverified":legacy}),
    ))
}
