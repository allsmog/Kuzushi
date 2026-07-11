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
    let out_root = prepare_shinsa_output_root(target, output_dir)?;
    let relative_root = out_root.strip_prefix(target).with_context(|| {
        format!(
            "Shinsa output directory {} must stay inside target {}",
            out_root.display(),
            target.display()
        )
    })?;
    let state_path = crate::workspace::write_workspace_file(
        target,
        relative_root.join("shinsa-state.json"),
        format!("{}\n", serde_json::to_string_pretty(&raw)?).as_bytes(),
    )?;
    let report_path = crate::workspace::write_workspace_file(
        target,
        relative_root.join("compliance-report.md"),
        format!("# Shinsa Compliance Report\n\nMode: {mode}\nFindings: {finding_count}\n")
            .as_bytes(),
    )?;

    Ok(ShinsaArtifacts {
        state_path,
        report_path,
    })
}

pub(super) fn prepare_shinsa_output_root(target: &Path, output_dir: &str) -> Result<PathBuf> {
    let requested_root = target.join(output_dir);
    let relative = requested_root.strip_prefix(target).with_context(|| {
        format!(
            "Shinsa output directory {} must stay inside target {}",
            requested_root.display(),
            target.display()
        )
    })?;
    crate::workspace::ensure_workspace_output_dir(target, relative)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn artifacts_reject_symlinked_output_directory() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), workspace.path().join("shinsa-output")).unwrap();

        assert!(write_shinsa_artifacts(
            workspace.path(),
            "shinsa-output",
            "full",
            0,
            &json!({"summary": "safe"}),
        )
        .is_err());
        assert!(std::fs::read_dir(outside.path()).unwrap().next().is_none());
    }
}
