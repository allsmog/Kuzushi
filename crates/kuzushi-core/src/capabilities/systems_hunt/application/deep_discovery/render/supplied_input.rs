use super::*;

pub(crate) fn prepare(prepared: &context::Prepared, request: &AgentQueryRequest) -> Result<Value> {
    let frozen: Value = serde_json::from_str(&prepared.prompt)?;
    let text = lines(
        &frozen,
        &request.system_prompt,
        &request.model,
        request.thinking_level.as_deref(),
    )
    .join("\n");
    Ok(
        json!({"inspection":prepared.inspection,"frozenInput":frozen,
        "systemPrompt":request.system_prompt,"model":request.model,"runtimeRequest":request,
        "inputDocument":{"schemaVersion":1,"text":text}}),
    )
}

fn lines(supplied: &Value, system: &str, model: &str, reasoning: Option<&str>) -> Vec<String> {
    let mut lines = header(supplied, model, reasoning);
    for source in supplied["sources"].as_array().into_iter().flatten() {
        lines.push(format!(
            "Source: {} · {}\n{}",
            source["path"].as_str().unwrap_or("unavailable"),
            source["role"].as_str().unwrap_or("unavailable"),
            source["text"].as_str().unwrap_or("")
        ));
    }
    for label in ["context", "threatModel"] {
        lines.push(format!(
            "{label}: {}",
            supplied["supportingContext"][label]
                .as_str()
                .unwrap_or("explicitly absent")
        ));
    }
    lines.push(format!(
        "Selected context references: threat model {}, supporting context {}",
        supplied["supportingContext"]["selectedThreatModelRef"],
        supplied["supportingContext"]["selectedScanContextRef"]
    ));
    lines.push(format!("System instructions:\n{system}"));
    lines
}

fn header(supplied: &Value, model: &str, reasoning: Option<&str>) -> Vec<String> {
    vec![
        "FROZEN MODEL INPUT".into(),
        format!("Tool: {TOOL}"),
        "Retained before runtime invocation. Provider delivery is not established by this document.".into(),
        "Module-supplied source and instructions. Adapter transformations are outside this record.".into(),
        "Historical supplied text; reading starts no work or source revalidation.".into(),
        format!("Model supplied: {model}"),
        format!(
            "Reasoning supplied: {}",
            reasoning.unwrap_or("not explicitly supplied")
        ),
        "Requested limits: one model turn; 4096 output tokens. Adapter support varies.".into(),
        format!(
            "Task supplied: {}",
            supplied["task"].as_str().unwrap_or("unavailable")
        ),
        format!("Maximum findings supplied: {}", supplied["maxFindings"]),
        format!("Selected classes supplied: {}", supplied["cwes"]),
        format!("Scope supplied: {}", supplied["scope"]),
        "Complete repository coverage supplied: false".into(),
    ]
}
