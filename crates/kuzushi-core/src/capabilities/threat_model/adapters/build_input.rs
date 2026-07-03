use super::*;

pub(crate) fn parse_build_input(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
) -> Result<BuildInput> {
    let target = resolve_target(input, ctx)?;
    let repo_name = repo_name(&target);
    let methodology = read_methodology(input, flavor.default_methodology());
    let sources = read_source_artifacts(input, flavor)?;
    let seeds = read_string_list(input, &["seed"]);
    let design_doc = read_string(input, &["designDoc", "design_doc", "design"]);
    let slice = read_slice(input);
    let stages = read_stages(input, flavor.tool_name())?;
    let run_id = Uuid::new_v4().to_string();
    let output_dir = read_string(input, &["outputDir", "output_dir"])
        .unwrap_or_else(|| flavor.default_output_dir(&target, &run_id));
    let context_mode = read_context_mode(input);
    let context_limit = read_usize(
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
    .min(2_000);
    let max_source_bytes = read_usize(input, &["maxSourceBytes", "max_source_bytes"], 200_000, 1);
    let max_elements = read_usize(input, &["maxElements", "max_elements"], 40, 5);
    let max_threats = read_usize(input, &["maxThreats", "max_threats"], 30, 1);
    let emit_findings = read_bool(input, &["emitFindings", "emit_findings"], false);
    let preserve_user_edits = read_bool(input, &["preserveUserEdits", "preserve_user_edits"], true);
    let prompt_override = read_string(input, &["THREAT_MODEL_PROMPT"])
        .map(|value| {
            crate::options::resolve_prompt_override_for_key(
                &value,
                &target,
                "THREAT_MODEL_PROMPT",
            )
        })
        .transpose()?;
    let model = crate::runtime::resolve_explicit_model(
        flavor.tool_name(),
        read_string(input, &["model"]),
        ctx.config.model.as_deref(),
    )?;

    Ok(BuildInput {
        target,
        repo_name,
        methodology,
        sources,
        seeds,
        design_doc,
        slice,
        stages,
        output_dir,
        context_mode,
        context_limit,
        max_source_bytes,
        max_elements,
        max_threats,
        emit_findings,
        preserve_user_edits,
        prompt_override,
        model,
    })
}

fn read_source_artifacts(input: &Value, flavor: BuildFlavor) -> Result<Vec<String>> {
    let mut sources = read_string_list(input, &["sources", "sourceArtifacts", "source_artifacts"]);
    if sources.is_empty() {
        sources = match flavor {
            BuildFlavor::ThreatModel => vec!["context".to_string(), "threat-model".to_string()],
            BuildFlavor::RandoriPasta => vec!["none".to_string()],
        };
    }
    let mut normalized = Vec::new();
    for source in sources {
        let source = source.to_lowercase();
        if !VALID_SOURCE_ARTIFACTS.contains(&source.as_str()) {
            anyhow::bail!(
                "threat-model:build sources contains unsupported value {source:?}; use one of {}",
                VALID_SOURCE_ARTIFACTS.join(", ")
            );
        }
        if !normalized.iter().any(|seen| seen == &source) {
            normalized.push(source);
        }
    }
    if normalized.iter().any(|source| source == "none") && normalized.len() > 1 {
        anyhow::bail!("threat-model:build sources value \"none\" cannot be combined with other sources");
    }
    Ok(normalized)
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
