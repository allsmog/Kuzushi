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

pub fn read_x_ray_report_artifacts(
    repo_root: &Path,
    repo_name: Option<&str>,
    runtime_mode: &str,
    cost_usd: f64,
) -> Result<XRayReportData> {
    let repo_root = canonicalize_report_root(repo_root)?;
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

    ensure_required_artifacts_exist(&paths)?;

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
            .unwrap_or_else(|| crate::capabilities::x_ray::domain::repo_name(&repo_root)),
        runtime_mode: runtime_mode.to_string(),
        artifact_paths: paths,
        verdict: parse_verdict(&x_ray_markdown),
        entry_point_counts: parse_entry_point_counts(&entry_points_markdown),
        invariant_counts: parse_invariant_counts(&invariants_markdown),
        cost_usd,
    })
}

fn canonicalize_report_root(path: &Path) -> Result<PathBuf> {
    let root = fs::canonicalize(path)
        .with_context(|| format!("Could not resolve target {}", path.display()))?;
    if !root.is_dir() {
        anyhow::bail!("Target must be a directory: {}", root.display());
    }
    Ok(root)
}

fn ensure_required_artifacts_exist(paths: &XRayArtifactPaths) -> Result<()> {
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
    Ok(())
}
