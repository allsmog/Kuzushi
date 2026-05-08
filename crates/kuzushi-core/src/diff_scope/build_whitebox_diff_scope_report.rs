use super::*;

pub fn build_whitebox_diff_scope_report(
    root: impl AsRef<Path>,
    diff_base: &str,
    current_findings: &[Finding],
    previous_findings: &[Finding],
) -> Result<WhiteboxDiffScopeReport> {
    let root = root
        .as_ref()
        .canonicalize()
        .with_context(|| format!("repository root {} does not exist", root.as_ref().display()))?;
    if !root.is_dir() {
        anyhow::bail!("repository root {} is not a directory", root.display());
    }

    let changed_files = collect_changed_files(&root, diff_base)?;
    let attack_surface = build_attack_surface_map(&root).ok();
    let context = expand_diff_context(&root, &changed_files, attack_surface.as_ref())?;
    let finding_tags = current_findings
        .iter()
        .map(|finding| tag_current_finding(finding, &changed_files))
        .collect::<Vec<_>>();
    let fixed_findings = tag_fixed_findings(previous_findings, current_findings, &changed_files);
    let summary = summarize_diff_scope(&changed_files, &context, &finding_tags, &fixed_findings);

    Ok(WhiteboxDiffScopeReport {
        diff_base: diff_base.to_string(),
        target: root.display().to_string(),
        changed_files,
        context,
        finding_tags,
        fixed_findings,
        summary,
        deterministic: true,
        no_remote_provider_required: true,
    })
}

pub(crate) fn collect_changed_files(root: &Path, diff_base: &str) -> Result<Vec<ChangedFile>> {
    verify_diff_base(root, diff_base)?;
    let mut files = parse_name_status(&git_output(
        root,
        &[
            "diff",
            "--name-status",
            "--find-renames",
            &format!("{diff_base}...HEAD"),
        ],
    )?);
    parse_unified_diff_ranges(
        &git_output(
            root,
            &[
                "diff",
                "--unified=0",
                "--no-color",
                "--no-ext-diff",
                "--find-renames",
                &format!("{diff_base}...HEAD"),
            ],
        )?,
        &mut files,
    );

    Ok(files.into_values().collect())
}

pub(crate) fn verify_diff_base(root: &Path, diff_base: &str) -> Result<()> {
    let output = Command::new("git")
        .args(["rev-parse", "--verify", diff_base])
        .current_dir(root)
        .output()
        .with_context(|| {
            "whitebox-static diff mode requires local git; install git or omit diffBase"
        })?;
    if !output.status.success() {
        anyhow::bail!(
            "whitebox-static diff mode could not resolve diffBase {:?}: {}",
            diff_base,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

pub(crate) fn git_output(root: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .with_context(|| {
            "whitebox-static diff mode requires local git; install git or omit diffBase"
        })?;
    if !output.status.success() {
        anyhow::bail!(
            "whitebox-static diff mode git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
