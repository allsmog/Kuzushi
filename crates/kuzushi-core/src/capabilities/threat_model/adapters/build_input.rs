use super::*;

pub(crate) fn parse_build_input(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
) -> Result<BuildInput> {
    let target = resolve_target(input, ctx)?;
    let context_mode = read_context_mode(input);
    let run_id = Uuid::new_v4().to_string();
    let output_dir = read_string(input, &["outputDir", "output_dir"])
        .unwrap_or_else(|| flavor.default_output_dir(&target, &run_id));
    Ok(BuildInput {
        repo_name: repo_name(&target),
        methodology: read_methodology(input, flavor.default_methodology()),
        sources: read_source_artifacts(input, flavor, &context_mode)?,
        seeds: read_string_list(input, &["seed"]),
        design_doc: read_string(input, &["designDoc", "design_doc", "design"]),
        slice: read_slice(input),
        stages: read_stages(input, flavor.tool_name())?,
        output_dir,
        context_mode,
        context_limit: context_limit(input),
        max_source_bytes: max_source_bytes(input),
        max_elements: read_usize(input, &["maxElements", "max_elements"], 40, 5),
        max_threats: read_usize(input, &["maxThreats", "max_threats"], 30, 1),
        emit_findings: read_bool(input, &["emitFindings", "emit_findings"], false),
        preserve_user_edits: read_bool(input, &["preserveUserEdits", "preserve_user_edits"], true),
        prompt_override: prompt_override(input, &target)?,
        model: build_model(input, ctx, flavor)?,
        target,
    })
}

fn context_limit(input: &Value) -> usize {
    read_usize(
        input,
        &[
            "contextLimit",
            "contextSampleLimit",
            "context_sample_limit",
            "sampleLimit",
        ],
        200,
        1,
    )
    .min(2_000)
}

fn max_source_bytes(input: &Value) -> usize {
    read_usize(input, &["maxSourceBytes", "max_source_bytes"], 200_000, 1)
        .min(MAX_SOURCE_BYTES)
}

fn prompt_override(input: &Value, target: &Path) -> Result<Option<String>> {
    read_string(input, &["THREAT_MODEL_PROMPT"])
        .map(|value| {
            crate::options::resolve_prompt_override_for_key(
                &value,
                target,
                "THREAT_MODEL_PROMPT",
            )
        })
        .transpose()
}

fn build_model(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
) -> Result<String> {
    crate::runtime::resolve_explicit_model(
        flavor.tool_name(),
        read_string(input, &["model"]),
        ctx.config.model.as_deref(),
    )
}

fn read_source_artifacts(
    input: &Value,
    flavor: BuildFlavor,
    context_mode: &str,
) -> Result<Vec<String>> {
    let sources = source_artifact_values(input, flavor);
    let normalized = normalize_source_artifacts(sources)?;
    reject_invalid_source_artifact_combo(&normalized)?;
    Ok(source_artifacts_for_context_mode(normalized, context_mode))
}

fn source_artifact_values(input: &Value, flavor: BuildFlavor) -> Vec<String> {
    let sources = read_string_list(input, &["sources", "sourceArtifacts", "source_artifacts"]);
    if sources.is_empty() {
        return default_source_artifacts(flavor);
    }
    sources
}

fn default_source_artifacts(flavor: BuildFlavor) -> Vec<String> {
    match flavor {
        BuildFlavor::ThreatModel => vec!["context".to_string(), "threat-model".to_string()],
        BuildFlavor::RandoriPasta => vec!["none".to_string()],
    }
}

fn normalize_source_artifacts(sources: Vec<String>) -> Result<Vec<String>> {
    let mut normalized = Vec::new();
    for source in sources {
        let source = source.to_lowercase();
        validate_source_artifact(&source)?;
        push_unique_source_artifact(&mut normalized, source);
    }
    Ok(normalized)
}

fn validate_source_artifact(source: &str) -> Result<()> {
    if !VALID_SOURCE_ARTIFACTS.contains(&source) {
        anyhow::bail!(
            "threat-model:build sources contains unsupported value {source:?}; use one of {}",
            VALID_SOURCE_ARTIFACTS.join(", ")
        );
    }
    Ok(())
}

fn push_unique_source_artifact(sources: &mut Vec<String>, source: String) {
    if !sources.iter().any(|seen| seen == &source) {
        sources.push(source);
    }
}

fn reject_invalid_source_artifact_combo(sources: &[String]) -> Result<()> {
    if sources.iter().any(|source| source == "none") && sources.len() > 1 {
        anyhow::bail!("threat-model:build sources value \"none\" cannot be combined with other sources");
    }
    Ok(())
}

fn source_artifacts_for_context_mode(sources: Vec<String>, context_mode: &str) -> Vec<String> {
    if context_mode == "off" && source_lists_match(&sources, &["context", "threat-model"]) {
        return vec!["none".to_string()];
    }
    sources
}

fn source_lists_match(actual: &[String], expected: &[&str]) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    expected
        .iter()
        .all(|expected| actual.iter().any(|actual| actual == expected))
}

fn read_context_mode(input: &Value) -> String {
    read_string(input, &["contextMode", "context_mode"])
        .map(|value| value.to_lowercase())
        .filter(|value| VALID_CONTEXT_MODES.contains(&value.as_str()))
        .unwrap_or_else(|| "auto".to_string())
}

pub(crate) fn read_string_list(input: &Value, keys: &[&str]) -> Vec<String> {
    keys.iter()
        .find_map(|key| match input.get(*key) {
            Some(Value::Array(items)) => Some(
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            ),
            Some(Value::String(value)) => Some(
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        })
        .unwrap_or_default()
}
