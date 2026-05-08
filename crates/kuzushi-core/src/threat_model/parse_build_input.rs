use super::*;

pub(crate) fn parse_build_input(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
) -> Result<BuildInput> {
    let target = resolve_target(input, ctx)?;
    let repo_name = repo_name(&target);
    let methodology = read_methodology(input, "pasta");
    let slice = read_string(input, &["slice"])
        .filter(|value| {
            matches!(
                value.as_str(),
                "all" | "dfd" | "stride" | "stories" | "scope" | "scenarios"
            )
        })
        .unwrap_or_else(|| "all".to_string());
    let stages = read_stages(input, flavor.tool_name())?;
    let run_id = Uuid::new_v4().to_string();
    let output_dir = read_string(input, &["outputDir", "output_dir"])
        .unwrap_or_else(|| format!(".kuzushi/runs/{run_id}/{}", flavor.default_artifact_leaf()));
    let max_elements = read_usize(input, &["maxElements", "max_elements"], 40, 5);
    let max_threats = read_usize(input, &["maxThreats", "max_threats"], 30, 1);
    let emit_findings = read_bool(input, &["emitFindings", "emit_findings"], false);
    let preserve_user_edits = read_bool(input, &["preserveUserEdits", "preserve_user_edits"], true);
    let model = read_string(input, &["model"])
        .or_else(|| ctx.config.model.clone())
        .with_context(|| {
            format!(
                "{} requires an explicit model in config.toml, KUZUSHI_MODEL, or the tool input; Kuzushi will not choose a fallback model",
                flavor.tool_name()
            )
        })?;

    Ok(BuildInput {
        target,
        repo_name,
        methodology,
        slice,
        stages,
        output_dir,
        max_elements,
        max_threats,
        emit_findings,
        preserve_user_edits,
        model,
    })
}
