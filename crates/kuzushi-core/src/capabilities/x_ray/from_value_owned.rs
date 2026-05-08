use super::*;

impl XRayArtifactContent {
    pub(crate) fn from_value_owned(value: Value) -> Result<Self> {
        Self::from_value(&value)
    }

    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let x_ray_markdown = string_any(value, &["xRayMarkdown", "xRay", "x_ray", "x-ray.md"])
            .context("missing xRayMarkdown artifact content")?;
        let entry_points_markdown = string_any(
            value,
            &[
                "entryPointsMarkdown",
                "entryPoints",
                "entry_points",
                "entry-points.md",
            ],
        )
        .context("missing entryPointsMarkdown artifact content")?;
        let invariants_markdown = string_any(
            value,
            &[
                "invariantsMarkdown",
                "invariants",
                "invariants_md",
                "invariants.md",
            ],
        )
        .context("missing invariantsMarkdown artifact content")?;
        let architecture_svg = string_any(
            value,
            &[
                "architectureSvg",
                "architectureSVG",
                "architecture",
                "architecture.svg",
            ],
        )
        .context("missing architectureSvg artifact content")?;

        Ok(Self {
            x_ray_markdown,
            entry_points_markdown,
            invariants_markdown,
            architecture_svg,
        })
    }
}

pub(crate) fn string_any(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key)?.as_str())
        .map(ToString::to_string)
        .filter(|value| !value.trim().is_empty())
}

pub(crate) fn write_x_ray_artifacts(repo_root: &Path, content: XRayArtifactContent) -> Result<()> {
    let artifact_dir = repo_root.join("x-ray");
    fs::create_dir_all(&artifact_dir)
        .with_context(|| format!("Could not create {}", artifact_dir.display()))?;
    fs::write(artifact_dir.join(REQUIRED_X_RAY_MD), content.x_ray_markdown)
        .context("Could not write x-ray.md")?;
    fs::write(
        artifact_dir.join(REQUIRED_ENTRY_POINTS_MD),
        content.entry_points_markdown,
    )
    .context("Could not write entry-points.md")?;
    fs::write(
        artifact_dir.join(REQUIRED_INVARIANTS_MD),
        content.invariants_markdown,
    )
    .context("Could not write invariants.md")?;
    fs::write(
        artifact_dir.join(REQUIRED_ARCHITECTURE_SVG),
        content.architecture_svg,
    )
    .context("Could not write architecture.svg")?;
    Ok(())
}

pub(crate) fn render_x_ray_run_summary(data: &XRayReportData) -> String {
    format!(
        "x-ray:run complete for {} ({})\n  Runtime:      {}\n  Verdict:      {}{}\n  Entry points: {}\n  Invariants:   {}\n  Cost:         ${}\n\nArtifacts:\n  - {}\n  - {}\n  - {}\n  - {}",
        data.repo_name,
        data.target,
        data.runtime_mode,
        data.verdict.tier.as_deref().unwrap_or("unknown"),
        if data.verdict.summary.is_empty() {
            String::new()
        } else {
            format!(" - {}", data.verdict.summary)
        },
        data.entry_point_counts.total,
        data.invariant_counts.total,
        format!("{:.4}", data.cost_usd),
        data.artifact_paths.x_ray,
        data.artifact_paths.entry_points,
        data.artifact_paths.invariants,
        data.artifact_paths.architecture_svg,
    )
}

pub(crate) fn render_x_ray_read_summary(data: &XRayReportData) -> String {
    format!(
        "x-ray:read validated artifacts for {} ({})\n  Verdict:      {}{}\n  Entry points: {}\n  Invariants:   {}",
        data.repo_name,
        data.target,
        data.verdict.tier.as_deref().unwrap_or("unknown"),
        if data.verdict.summary.is_empty() {
            String::new()
        } else {
            format!(" - {}", data.verdict.summary)
        },
        data.entry_point_counts.total,
        data.invariant_counts.total,
    )
}
