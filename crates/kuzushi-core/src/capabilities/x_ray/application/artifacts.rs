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
    write_x_ray_artifact(repo_root, REQUIRED_X_RAY_MD, &content.x_ray_markdown)?;
    write_x_ray_artifact(
        repo_root,
        REQUIRED_ENTRY_POINTS_MD,
        &content.entry_points_markdown,
    )?;
    write_x_ray_artifact(
        repo_root,
        REQUIRED_INVARIANTS_MD,
        &content.invariants_markdown,
    )?;
    write_x_ray_artifact(
        repo_root,
        REQUIRED_ARCHITECTURE_SVG,
        &content.architecture_svg,
    )?;
    Ok(())
}

fn write_x_ray_artifact(repo_root: &Path, file_name: &str, content: &str) -> Result<PathBuf> {
    crate::workspace::write_workspace_file(
        repo_root,
        Path::new("x-ray").join(file_name),
        content.as_bytes(),
    )
    .with_context(|| format!("Could not write x-ray/{file_name}"))
}

pub(crate) fn render_x_ray_run_summary(data: &XRayReportData) -> String {
    format!(
        "x-ray:run complete for {} ({})\n  Runtime:      {}\n  Verdict:      {}{}\n  Entry points: {}\n  Invariants:   {}\n  Cost:         {}\n\nArtifacts:\n  - {}\n  - {}\n  - {}\n  - {}",
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
        x_ray_cost_label(data),
        data.artifact_paths.x_ray,
        data.artifact_paths.entry_points,
        data.artifact_paths.invariants,
        data.artifact_paths.architecture_svg,
    )
}

/// An unresolved provider spend is a lower bound, never an exact `$0`.
fn x_ray_cost_label(data: &XRayReportData) -> String {
    match (data.cost_usd_exact, data.estimated_cost_usd) {
        (true, _) => format!("${:.4}", data.cost_usd),
        (false, Some(estimate)) => format!("~${estimate:.4} estimated (provider spend unresolved)"),
        (false, None) => format!(">=${:.4} (provider spend unresolved)", data.cost_usd),
    }
}

pub(crate) fn render_x_ray_read_summary(data: &XRayReportData) -> String {
    format!(
        "x-ray:read loaded artifacts for {}\n  Recorded report tier: {}{}\n  Entry points parsed from report: {}\n  Invariants parsed from report: {}\nSource freshness: not assessed. Report claims do not establish a finding verdict or accept Map.\nOriginal generation spend, model, runtime and context: unknown. The reader makes no provider requests.\nArchitecture file is bounded; graph semantics are not assessed.\nTarget: {}\nFiles under x-ray/:\n  {}\n  {}\n  {}\n  {}",
        data.repo_name,
        data.verdict.tier.as_deref().unwrap_or("unknown"),
        if data.verdict.summary.is_empty() {
            String::new()
        } else {
            format!(" - {}", data.verdict.summary)
        },
        data.entry_point_counts.total,
        data.invariant_counts.total,
        data.target,
        REQUIRED_X_RAY_MD,
        REQUIRED_ENTRY_POINTS_MD,
        REQUIRED_INVARIANTS_MD,
        REQUIRED_ARCHITECTURE_SVG,
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
    let paths = x_ray_artifact_paths(&artifact_dir);
    ensure_required_artifacts_exist(&repo_root, &paths)?;
    crate::bounded_file::read_regular_bytes_within(
        &repo_root,
        Path::new(&paths.architecture_svg),
        8 * 1024 * 1024,
    )
    .context("Unable to read bounded architecture artifact")?;
    let markdown = read_x_ray_markdown(&repo_root, &paths)?;

    Ok(XRayReportData {
        target: repo_root.display().to_string(),
        repo_name: report_repo_name(repo_name, &repo_root),
        runtime_mode: runtime_mode.to_string(),
        artifact_paths: paths,
        verdict: parse_verdict(&markdown.x_ray),
        entry_point_counts: parse_entry_point_counts(&markdown.entry_points),
        invariant_counts: parse_invariant_counts(&markdown.invariants),
        cost_usd,
        cost_usd_exact: true,
        estimated_cost_usd: None,
    })
}

struct XRayMarkdown {
    x_ray: String,
    entry_points: String,
    invariants: String,
}

fn x_ray_artifact_paths(artifact_dir: &Path) -> XRayArtifactPaths {
    XRayArtifactPaths {
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
    }
}

fn read_x_ray_markdown(repo_root: &Path, paths: &XRayArtifactPaths) -> Result<XRayMarkdown> {
    Ok(XRayMarkdown {
        x_ray: read_artifact_markdown(repo_root, &paths.x_ray)?,
        entry_points: read_artifact_markdown(repo_root, &paths.entry_points)?,
        invariants: read_artifact_markdown(repo_root, &paths.invariants)?,
    })
}

fn read_artifact_markdown(repo_root: &Path, path: &str) -> Result<String> {
    crate::bounded_file::read_utf8_text_within(repo_root, Path::new(path), 8 * 1024 * 1024)
        .with_context(|| format!("Unable to read {path}"))
}

fn report_repo_name(repo_name: Option<&str>, repo_root: &Path) -> String {
    repo_name
        .map(ToString::to_string)
        .unwrap_or_else(|| crate::capabilities::x_ray::domain::repo_name(repo_root))
}

fn canonicalize_report_root(path: &Path) -> Result<PathBuf> {
    let root = fs::canonicalize(path)
        .with_context(|| format!("Could not resolve target {}", path.display()))?;
    if !root.is_dir() {
        anyhow::bail!("Target must be a directory: {}", root.display());
    }
    Ok(root)
}

fn ensure_required_artifacts_exist(repo_root: &Path, paths: &XRayArtifactPaths) -> Result<()> {
    let required = [
        PathBuf::from(&paths.x_ray),
        PathBuf::from(&paths.entry_points),
        PathBuf::from(&paths.invariants),
        PathBuf::from(&paths.architecture_svg),
    ];
    let invalid = required
        .iter()
        .filter(|candidate| {
            crate::workspace::validated_workspace_descendant(
                repo_root,
                candidate.strip_prefix(repo_root).unwrap_or(candidate),
            )
            .is_err()
                || !std::fs::symlink_metadata(candidate).is_ok_and(|metadata| {
                    metadata.file_type().is_file() && !metadata.file_type().is_symlink()
                })
        })
        .map(|candidate| candidate.display().to_string())
        .collect::<Vec<_>>();
    if !invalid.is_empty() {
        anyhow::bail!(
            "X-Ray report is missing or has unsafe required artifact(s): {}",
            invalid.join(", ")
        );
    }
    Ok(())
}

#[cfg(test)]
mod writer_tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn x_ray_writer_rejects_symlinked_artifact_directory() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), workspace.path().join("x-ray")).unwrap();
        let content = XRayArtifactContent {
            x_ray_markdown: "# X-Ray".to_string(),
            entry_points_markdown: "# Entry points".to_string(),
            invariants_markdown: "# Invariants".to_string(),
            architecture_svg: "<svg/>".to_string(),
        };

        assert!(write_x_ray_artifacts(workspace.path(), content).is_err());
        assert!(std::fs::read_dir(outside.path()).unwrap().next().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn x_ray_reader_rejects_symlinked_required_artifact() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let artifact_dir = workspace.path().join("x-ray");
        std::fs::create_dir(&artifact_dir).unwrap();
        for (leaf, body) in [
            (REQUIRED_X_RAY_MD, "# X-Ray"),
            (REQUIRED_ENTRY_POINTS_MD, "# Entry Points"),
            (REQUIRED_INVARIANTS_MD, "# Invariants"),
        ] {
            std::fs::write(artifact_dir.join(leaf), body).unwrap();
        }
        symlink(outside.path(), artifact_dir.join(REQUIRED_ARCHITECTURE_SVG)).unwrap();

        let error = read_x_ray_report_artifacts(workspace.path(), None, "test", 0.0)
            .unwrap_err()
            .to_string();

        assert!(error.contains("unsafe required artifact"));
    }
}
