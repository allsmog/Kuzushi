use super::*;

#[derive(Debug)]
pub(crate) struct DeterministicBuildInput {
    pub(crate) target: PathBuf,
    pub(crate) repo_name: String,
    pub(crate) methodology: String,
    pub(crate) slice: String,
    pub(crate) stages: Vec<String>,
    pub(crate) output_dir: String,
    pub(crate) max_threats: usize,
    pub(crate) preserve_user_edits: bool,
}

pub(crate) fn parse_deterministic_build_input(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
) -> Result<DeterministicBuildInput> {
    let target = resolve_target(input, ctx)?;
    let run_id = Uuid::new_v4().to_string();
    let methodology = read_methodology(input, flavor.default_methodology());
    Ok(DeterministicBuildInput {
        repo_name: repo_name(&target),
        stages: read_stages(input, flavor.tool_name(), &methodology)?,
        methodology,
        slice: read_slice(input),
        output_dir: read_string(input, &["outputDir", "output_dir"])
            .unwrap_or_else(|| flavor.default_output_dir(&target, &run_id)),
        max_threats: read_usize(input, &["maxThreats", "max_threats"], 30, 1),
        preserve_user_edits: read_bool(input, &["preserveUserEdits", "preserve_user_edits"], true),
        target,
    })
}

pub(crate) fn read_slice(input: &Value) -> String {
    read_string(input, &["slice"])
        .filter(|value| {
            matches!(
                value.as_str(),
                "all" | "dfd" | "stride" | "stories" | "scope" | "scenarios"
            )
        })
        .unwrap_or_else(|| "all".to_string())
}
