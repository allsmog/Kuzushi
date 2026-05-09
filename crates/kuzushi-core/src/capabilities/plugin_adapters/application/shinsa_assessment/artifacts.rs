use super::*;

pub(crate) struct ShinsaArtifacts {
    pub(crate) state_path: PathBuf,
    pub(crate) report_path: PathBuf,
}

pub(super) fn write_shinsa_artifacts(
    target: &Path,
    output_dir: &str,
    mode: &str,
    finding_count: usize,
    raw: &Value,
) -> Result<ShinsaArtifacts> {
    let out_root = target.join(output_dir);
    fs::create_dir_all(&out_root)
        .with_context(|| format!("Could not create {}", out_root.display()))?;
    let state_path = out_root.join("shinsa-state.json");
    let report_path = out_root.join("compliance-report.md");
    fs::write(
        &state_path,
        format!("{}\n", serde_json::to_string_pretty(&raw)?),
    )?;
    fs::write(
        &report_path,
        format!("# Shinsa Compliance Report\n\nMode: {mode}\nFindings: {finding_count}\n"),
    )?;

    Ok(ShinsaArtifacts {
        state_path,
        report_path,
    })
}
