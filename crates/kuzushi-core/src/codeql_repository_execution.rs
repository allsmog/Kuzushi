use crate::remediation::patch::with_disposable_worktree;
use crate::remediation::patch_process_adapter::PatchProcessControl as PatchCommandControl;
use anyhow::{Context, Result};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

mod promotion;

pub(crate) use promotion::codeql_database_is_valid;
use promotion::{inspect_destination, promote_database, DestinationState};

pub(crate) const DEFAULT_CODEQL_REPOSITORY_TIMEOUT_MS: u64 = 30 * 60 * 1000;
pub(crate) const MAX_CODEQL_REPOSITORY_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Clone, Copy)]
pub(crate) enum CodeqlBuildStrategy<'a> {
    BuildMode(&'a str),
    Manual(&'a str),
}

pub(crate) struct CodeqlRepositoryBuild<'a> {
    pub source_root: &'a Path,
    pub source_commit: &'a str,
    pub destination: &'a Path,
    pub launcher: &'a Path,
    pub language: &'a str,
    pub strategy: CodeqlBuildStrategy<'a>,
    pub cancellation: Option<&'a crate::scan::ScanCancellation>,
    pub timeout: Duration,
}

pub(crate) fn run_codeql_repository_build(request: CodeqlRepositoryBuild<'_>) -> Result<Output> {
    let relative = validated_database_relative(request.source_root, request.destination)?;
    let destination_state = inspect_destination(request.destination)?;
    let control = PatchCommandControl::new(request.cancellation, request.timeout);
    with_disposable_worktree(
        request.source_root,
        request.source_commit,
        control,
        |checkout| run_in_checkout(&request, &relative, destination_state, checkout, control),
    )
}

fn run_in_checkout(
    request: &CodeqlRepositoryBuild<'_>,
    relative: &Path,
    destination_state: DestinationState,
    checkout: &Path,
    control: PatchCommandControl<'_>,
) -> Result<Output> {
    let isolated_db = crate::workspace::prepare_workspace_output_path(checkout, relative)?;
    let launcher = isolated_launcher(request.source_root, checkout, request.launcher)?;
    let args = codeql_arguments(relative, request.language, request.strategy, checkout)?;
    let output =
        control.run_program(checkout, &launcher, &args, "isolated CodeQL database build")?;
    if output.status.success() {
        promote_database(
            request.source_root,
            &isolated_db,
            request.destination,
            destination_state,
        )?;
    }
    Ok(output)
}

fn codeql_arguments(
    relative_db: &Path,
    language: &str,
    strategy: CodeqlBuildStrategy<'_>,
    checkout: &Path,
) -> Result<Vec<OsString>> {
    let mut args = vec![
        "database".into(),
        "create".into(),
        relative_db.as_os_str().to_owned(),
        format!("--language={language}").into(),
        "--source-root=.".into(),
        "--overwrite".into(),
    ];
    append_build_strategy(&mut args, strategy, checkout)?;
    Ok(args)
}

fn append_build_strategy(
    args: &mut Vec<OsString>,
    strategy: CodeqlBuildStrategy<'_>,
    checkout: &Path,
) -> Result<()> {
    match strategy {
        CodeqlBuildStrategy::BuildMode("default") => {}
        CodeqlBuildStrategy::BuildMode(mode) => args.push(format!("--build-mode={mode}").into()),
        CodeqlBuildStrategy::Manual(command) => append_manual_strategy(args, checkout, command)?,
    }
    Ok(())
}

fn append_manual_strategy(args: &mut Vec<OsString>, checkout: &Path, command: &str) -> Result<()> {
    let script = write_manual_build_script(checkout, command)?;
    let relative = script
        .strip_prefix(checkout)
        .context("CodeQL build script escaped its isolated checkout")?;
    args.push(format!("--command=bash {}", relative.display()).into());
    Ok(())
}

fn write_manual_build_script(checkout: &Path, command: &str) -> Result<PathBuf> {
    let relative = Path::new(".kuzushi/codeql-build.sh");
    let body =
        format!("#!/usr/bin/env bash\nset -euo pipefail\ncd \"$(dirname \"$0\")/..\"\n{command}\n");
    crate::workspace::write_workspace_state_file(checkout, relative, body.as_bytes())
}

fn isolated_launcher(source_root: &Path, checkout: &Path, launcher: &Path) -> Result<PathBuf> {
    let source_root = fs::canonicalize(source_root)
        .with_context(|| format!("could not resolve source root {}", source_root.display()))?;
    let launcher = fs::canonicalize(launcher)
        .with_context(|| format!("could not resolve CodeQL launcher {}", launcher.display()))?;
    match launcher.strip_prefix(&source_root) {
        Ok(relative) => Ok(checkout.join(relative)),
        Err(_) => Ok(launcher),
    }
}

fn validated_database_relative(source_root: &Path, destination: &Path) -> Result<PathBuf> {
    let source_root = fs::canonicalize(source_root)
        .with_context(|| format!("could not resolve source root {}", source_root.display()))?;
    let relative = destination.strip_prefix(&source_root).with_context(|| {
        format!(
            "CodeQL database output {} must stay inside target {}",
            destination.display(),
            source_root.display()
        )
    })?;
    anyhow::ensure!(
        relative.starts_with(crate::workspace::KUZUSHI_STATE_DIR),
        "CodeQL database output {} must stay below .kuzushi",
        destination.display()
    );
    crate::workspace::prepare_workspace_output_path(&source_root, relative)?;
    Ok(relative.to_path_buf())
}
