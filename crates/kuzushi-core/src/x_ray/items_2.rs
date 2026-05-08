use super::prelude::*;
use super::*;

pub(crate) fn run_x_ray(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let runtime = runtime.context(
        "x-ray:run requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )?;
    let input = parse_run_input(&input, ctx)?;
    let prompt = build_x_ray_prompt(&input);
    let content = query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            input.model.clone(),
            input.target.clone(),
            X_RAY_SYSTEM_PROMPT.to_string(),
            prompt,
        ),
        StructuredJsonContract::new("x-ray:run", "XRayArtifactContent", x_ray_artifact_schema()),
        XRayArtifactContent::from_value_owned,
    )?;
    write_x_ray_artifacts(&input.target, content)?;

    let data =
        read_x_ray_report_artifacts(&input.target, Some(&input.repo_name), "pi-agent-core", 0.0)?;
    let mut data_json = json!(data);
    data_json["kbContext"] = json!(&input.kb_context);
    Ok(json!({
        "ok": true,
        "output": render_x_ray_run_summary(&data),
        "data": data_json,
        "costUsd": 0.0,
    }))
}

pub(crate) fn read_x_ray(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_target(&input, ctx)?;
    let repo_name = repo_name(&target);
    let data = read_x_ray_report_artifacts(&target, Some(&repo_name), "rust", 0.0)?;
    Ok(json!({
        "ok": true,
        "output": render_x_ray_read_summary(&data),
        "data": data,
    }))
}

pub fn read_x_ray_report_artifacts(
    repo_root: &Path,
    repo_name: Option<&str>,
    runtime_mode: &str,
    cost_usd: f64,
) -> Result<XRayReportData> {
    let repo_root = canonicalize_dir(repo_root)?;
    let artifact_dir = repo_root.join("x-ray");
    let paths = XRayArtifactPaths {
        x_ray: artifact_dir.join(REQUIRED_X_RAY_MD).display().to_string(),
        entry_points: artifact_dir
            .join(REQUIRED_ENTRY_POINTS_MD)
            .display()
            .to_string(),
        invariants: artifact_dir
            .join(REQUIRED_INVARIANTS_MD)
            .display()
            .to_string(),
        architecture_svg: artifact_dir
            .join(REQUIRED_ARCHITECTURE_SVG)
            .display()
            .to_string(),
    };

    let required = [
        PathBuf::from(&paths.x_ray),
        PathBuf::from(&paths.entry_points),
        PathBuf::from(&paths.invariants),
        PathBuf::from(&paths.architecture_svg),
    ];
    let missing = required
        .iter()
        .filter(|candidate| !candidate.exists())
        .map(|candidate| candidate.display().to_string())
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        anyhow::bail!(
            "X-Ray report is missing required artifact(s): {}",
            missing.join(", ")
        );
    }

    let x_ray_markdown = fs::read_to_string(&paths.x_ray)
        .with_context(|| format!("Unable to read {}", paths.x_ray))?;
    let entry_points_markdown = fs::read_to_string(&paths.entry_points)
        .with_context(|| format!("Unable to read {}", paths.entry_points))?;
    let invariants_markdown = fs::read_to_string(&paths.invariants)
        .with_context(|| format!("Unable to read {}", paths.invariants))?;

    Ok(XRayReportData {
        target: repo_root.display().to_string(),
        repo_name: repo_name
            .map(ToString::to_string)
            .unwrap_or_else(|| self::repo_name(&repo_root)),
        runtime_mode: runtime_mode.to_string(),
        artifact_paths: paths,
        verdict: parse_verdict(&x_ray_markdown),
        entry_point_counts: parse_entry_point_counts(&entry_points_markdown),
        invariant_counts: parse_invariant_counts(&invariants_markdown),
        cost_usd,
    })
}
