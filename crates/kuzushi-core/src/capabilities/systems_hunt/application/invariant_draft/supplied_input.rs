use super::*;

pub(super) fn prepare(prepared: &context::Prepared, request: &AgentQueryRequest) -> Result<Value> {
    let frozen: Value = serde_json::from_str(&prepared.prompt)?;
    let text = lines(&frozen, request).join("\n");
    Ok(
        json!({"inspection":prepared.inspection,"frozenInput":frozen,
        "systemPrompt":request.system_prompt,"model":request.model,"runtimeRequest":request,
        "inputDocument":{"schemaVersion":1,"text":text}}),
    )
}

fn lines(frozen: &Value, request: &AgentQueryRequest) -> Vec<String> {
    let mut lines = vec!["FROZEN MODEL INPUT".into()];
    for source in frozen["sources"].as_array().into_iter().flatten() {
        lines.push(format!(
            "Source: {}\n{}",
            source["path"].as_str().unwrap_or("unavailable"),
            source["text"].as_str().unwrap_or("")
        ));
    }
    lines.push("Historical supplied text. Reading starts no work.".into());
    lines.push("Surface anchors are unverified. Only ids, paths and lines were supplied. Lexical annotations, caller coverage metadata and surface packs were omitted.".into());
    for surface in frozen["surfaces"].as_array().into_iter().flatten() {
        append_surface(&mut lines, surface);
    }
    append_settings(&mut lines, frozen, request);
    append_supporting_context(&mut lines, &frozen["supportingContext"]);
    lines.push(format!("System instructions:\n{}", request.system_prompt));
    lines
}

fn append_settings(lines: &mut Vec<String>, frozen: &Value, request: &AgentQueryRequest) {
    lines.extend([format!("Tool: {TOOL}"),
        "Retained before runtime invocation; provider delivery is not established. Adapter transformations are outside this record.".into(),
        format!("Model supplied: {}", request.model),
        format!("Reasoning supplied: {}", request.thinking_level.as_deref().unwrap_or("not explicitly supplied; selected runtime setting retained")),
        "Requested limits: one model turn; 4096 output tokens. Adapter support varies.".into(),
        format!("Task supplied: {}", frozen["task"]), format!("Maximum drafts supplied: {}", frozen["maxInvariants"]),
        format!("Scope supplied: {}", frozen["scope"]), "Complete repository coverage supplied: false".into()]);
}

fn append_surface(lines: &mut Vec<String>, surface: &Value) {
    lines.extend([
        format!("Surface id: {}", value(&surface["id"])),
        format!(
            "Surface source: {}:{}",
            value(&surface["filePath"]),
            surface["startLine"]
        ),
    ]);
}

fn append_supporting_context(lines: &mut Vec<String>, context: &Value) {
    for label in [
        "context",
        "threatModel",
        "selectedThreatModelRef",
        "selectedScanContextRef",
    ] {
        lines.push(format!("{label}: {}", value(&context[label])));
    }
}

fn value(value: &Value) -> String {
    if value.is_null() {
        return "explicitly absent".into();
    }
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}
