use super::*;

#[derive(Debug)]
pub(crate) struct DeterministicBuildInput {
    pub(crate) roots: ThreatModelBuildRoots,
    pub(crate) repo_name: String,
    pub(crate) methodology: String,
    pub(crate) slice: String,
    pub(crate) stages: Vec<String>,
    pub(crate) output_dir: String,
    pub(crate) max_threats: usize,
    pub(crate) preserve_user_edits: bool,
    pub(crate) model_id: Option<ThreatModelId>,
    pub(crate) new_model: bool,
    pub(crate) activate: Option<bool>,
}

impl DeterministicBuildInput {
    pub(crate) fn workspace_root(&self) -> &Path {
        &self.roots.workspace_root
    }

    pub(crate) fn analysis_root(&self) -> &Path {
        &self.roots.analysis_root
    }
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
        roots: read_build_roots(input, &target)?,
        repo_name: repo_name(&target),
        stages: read_stages(input, flavor.tool_name(), &methodology)?,
        methodology,
        slice: read_slice(input),
        output_dir: read_string(input, &["outputDir", "output_dir"])
            .unwrap_or_else(|| flavor.default_output_dir(&target, &run_id)),
        max_threats: read_usize(input, &["maxThreats", "max_threats"], 30, 1),
        preserve_user_edits: read_bool(input, &["preserveUserEdits", "preserve_user_edits"], true),
        model_id: read_string(input, &["modelId", "model_id"])
            .map(ThreatModelId::parse)
            .transpose()?,
        new_model: read_bool(input, &["newModel", "new_model"], false),
        activate: input.get("activate").and_then(Value::as_bool),
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
