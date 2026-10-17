use super::*;

pub(super) fn result(output: SystemsContextOutput) -> Result<Value> {
    let receipt = output
        .metadata
        .inspection
        .as_ref()
        .context("bounded context receipt missing")?;
    let summary = format!(
        "systems-hunt context: {} surface(s); {} inspection",
        output.surfaces.len(),
        receipt["status"].as_str().unwrap_or("unavailable")
    );
    let text = render(&output, &summary, receipt);
    let mut result = crate::module_result::completed_output_result(&summary, &text, json!(output));
    if receipt["status"] == "partial" {
        result = crate::module_result::partial_output_result(
            &summary,
            &text,
            vec![json!(
                "Partial context. Inspect coverage before selecting further work."
            )],
            json!(output),
        );
    }
    result["costUsd"] = json!(0.0);
    Ok(result)
}

fn render(output: &SystemsContextOutput, summary: &str, receipt: &Value) -> String {
    let mut lines = context_summary(output, summary, receipt);
    for surface in &output.surfaces {
        lines.push(format!(
            "{}:{} · {} · score {}",
            surface.file_path, surface.start_line, surface.kind, surface.score
        ));
    }
    append_coverage(&mut lines, receipt);
    lines.join("\n")
}

fn context_summary(output: &SystemsContextOutput, summary: &str, receipt: &Value) -> Vec<String> {
    vec![
        summary.into(),
        format!(
            "Source prefixes: {} files, {} bytes inspected.",
            output.metadata.systems_source_files, receipt["inspectedSourceBytes"]
        ),
        format!(
            "Exact UTF-8 text retained: {} bytes; incomplete trailing UTF-8 bytes omitted: {}.",
            receipt["includedSourceTextBytes"], receipt["incompleteUtf8PrefixBytes"]
        ),
        "Coverage: selected systems source prefixes, never complete repository coverage.".into(),
        "Ranking: lexical signals, not vulnerability verdicts.".into(),
        "Code index / CodeQL: not requested. No source execution or model calls.".into(),
        format!(
            "Limits: {} files, {} source bytes, {} bytes/file, {} surfaces.",
            receipt["maxSourceFiles"],
            receipt["maxSourceBytes"],
            receipt["maxFileBytes"],
            receipt["maxSurfaces"]
        ),
        format!(
            "Omitted: {} source files, {} surfaces. Truncated: {} source files.",
            receipt["omittedSourceFiles"],
            receipt["omittedSurfaces"],
            receipt["truncatedSourceFiles"]
        ),
        format!(
            "Capped evidence: {} files, {} packs.",
            receipt["evidenceLimitedFiles"], receipt["siteLimitedPacks"]
        ),
        "Further analysis requires a separate explicit action.".into(),
    ]
}

pub(super) fn append_coverage(lines: &mut Vec<String>, receipt: &Value) {
    let inventory = &receipt["inventory"];
    lines.push(format!(
        "Inventory: {} entries examined; {} bytes inspected.",
        inventory["entries"], inventory["inspectedBytes"]
    ));
    if !inventory["truncation"].is_null() {
        lines.push(format!("Inventory limit: {}", inventory["truncation"]));
    }
    append_paths(lines, "Source exclusion or omission", &receipt["omissions"]);
    append_paths(lines, "Truncated source prefix", &receipt["truncatedPaths"]);
    append_paths(
        lines,
        "Inventory exclusion or omission",
        &inventory["omissions"],
    );
    append_paths(
        lines,
        "Inventory truncated prefix",
        &inventory["truncatedPaths"],
    );
    lines.push(format!(
        "Additional source disclosures: {} omissions, {} truncated paths.",
        receipt["additionalOmissions"], receipt["additionalTruncatedPaths"]
    ));
    lines.push("Full coverage receipt is included in the result.".into());
}

fn append_paths(lines: &mut Vec<String>, label: &str, paths: &Value) {
    let Some(paths) = paths.as_array() else {
        return;
    };
    for path in paths {
        lines.push(format!("{label}: {}", path_description(path)));
    }
}

fn path_description(path: &Value) -> String {
    if let Some(text) = path.as_str() {
        return text.into();
    }
    format!(
        "{}: {}",
        path["path"].as_str().unwrap_or("unavailable path"),
        path["reason"].as_str().unwrap_or("inspection limited")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_text_discloses_paths_without_copying_structured_json_into_transcript() {
        let receipt = json!({"inventory":{"entries":4,"inspectedBytes":64,"truncation":null,
            "omissions":[{"path":"vendor","reason":"ignored directory"}],"truncatedPaths":[]},
            "omissions":[{"path":"owned path.c","reason":"file limit"}],
            "truncatedPaths":["prefix.rs"],"additionalOmissions":0,"additionalTruncatedPaths":0});
        let mut lines = Vec::new();
        append_coverage(&mut lines, &receipt);
        let output = lines.join("\n");
        assert!(output.contains("owned path.c: file limit"));
        assert!(output.contains("Truncated source prefix: prefix.rs"));
        assert!(output.contains("vendor: ignored directory"));
        assert!(!output.contains("\"omissions\""));
        assert!(lines.len() < 10);
    }
}
