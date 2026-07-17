use super::*;
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::process::Output;
use std::time::Instant;

mod blob_batch;
mod git_repo;
mod manifest;

use self::blob_batch::extract_blob_batch;
use self::git_repo::install_minimal_git_repository;
use self::manifest::{load_bound_tree_manifest, BoundTreeManifest};

const MATERIALIZATION_LABEL: &str = "patch tree materialization";

#[derive(Clone, Copy)]
struct MaterializationLimits {
    max_files: usize,
    max_file_bytes: u64,
    max_total_bytes: u64,
    max_path_bytes: usize,
    max_index_bytes: usize,
    max_batch_request_bytes: usize,
    max_batch_stream_bytes: u64,
    max_commit_bytes: usize,
}

const MATERIALIZATION_LIMITS: MaterializationLimits = MaterializationLimits {
    max_files: 100_000,
    max_file_bytes: 1024 * 1024 * 1024,
    max_total_bytes: 4 * 1024 * 1024 * 1024,
    max_path_bytes: 16 * 1024 * 1024,
    max_index_bytes: 16 * 1024 * 1024,
    max_batch_request_bytes: 16 * 1024 * 1024,
    max_batch_stream_bytes: 4 * 1024 * 1024 * 1024 + 32 * 1024 * 1024,
    max_commit_bytes: 1024 * 1024,
};

pub(super) fn materialize_bound_commit(
    repo_root: &Path,
    checkout: &Path,
    source_commit: &str,
    control: PatchCommandControl<'_>,
) -> Result<()> {
    let deadline = control.deadline(MATERIALIZATION_LABEL)?;
    let parent = checkout
        .parent()
        .context("patch worktree path has no parent")?;
    let case_insensitive = filesystem_is_case_insensitive(parent)?;
    let manifest = load_bound_tree_manifest(
        repo_root,
        source_commit,
        control,
        deadline,
        MATERIALIZATION_LIMITS,
        case_insensitive,
    )?;
    let mut batch = capture_blob_batch(repo_root, &manifest, control, deadline, parent)?;
    ensure_materialization_active(control, deadline)?;
    std::fs::create_dir(checkout).with_context(|| {
        format!(
            "patch:finding could not create disposable checkout {}",
            checkout.display()
        )
    })?;
    extract_blob_batch(&mut batch, checkout, &manifest, control, deadline)?;
    install_minimal_git_repository(checkout, &manifest, control, deadline)?;
    Ok(())
}

fn capture_blob_batch(
    repo_root: &Path,
    manifest: &BoundTreeManifest,
    control: PatchCommandControl<'_>,
    deadline: Instant,
    temp_parent: &Path,
) -> Result<File> {
    let mut file = tempfile::tempfile_in(temp_parent)
        .context("patch:finding could not create bounded tree spool")?;
    let input = manifest.batch_request();
    let output = run_git_input_to_file_until(
        control,
        deadline,
        repo_root,
        &["cat-file", "--batch"],
        &input,
        file.try_clone()
            .context("patch:finding could not duplicate tree spool handle")?,
        manifest.batch_output_bound(),
        "git stream bound patch blobs",
    )?;
    ensure_git_success(&output, "stream bound patch blobs")?;
    let written = file
        .metadata()
        .context("patch:finding could not inspect bounded tree spool")?
        .len();
    anyhow::ensure!(
        written <= manifest.batch_output_bound(),
        "patch:finding bound tree batch exceeded its preflight byte bound"
    );
    file.seek(SeekFrom::Start(0))
        .context("patch:finding could not rewind bounded tree spool")?;
    Ok(file)
}

fn filesystem_is_case_insensitive(parent: &Path) -> Result<bool> {
    let probe = tempfile::tempdir_in(parent)
        .context("patch:finding could not create filesystem collision probe")?;
    let mixed = probe.path().join("KuzushiCaseProbe");
    std::fs::write(&mixed, b"probe")
        .context("patch:finding could not write filesystem collision probe")?;
    Ok(probe.path().join("kuzushicaseprobe").exists())
}

fn ensure_materialization_active(
    control: PatchCommandControl<'_>,
    deadline: Instant,
) -> Result<()> {
    control
        .remaining_until(deadline, MATERIALIZATION_LABEL)
        .map(|_| ())
}

fn run_git_until(
    control: PatchCommandControl<'_>,
    deadline: Instant,
    cwd: &Path,
    args: &[&str],
    label: &str,
) -> Result<Output> {
    control
        .remaining_until(deadline, MATERIALIZATION_LABEL)?
        .run_git(cwd, args, label)
}

fn run_git_input_until(
    control: PatchCommandControl<'_>,
    deadline: Instant,
    cwd: &Path,
    args: &[&str],
    input: &[u8],
    label: &str,
) -> Result<Output> {
    control
        .remaining_until(deadline, MATERIALIZATION_LABEL)?
        .run_git_with_input(cwd, args, input, label)
}

fn run_git_input_to_file_until(
    control: PatchCommandControl<'_>,
    deadline: Instant,
    cwd: &Path,
    args: &[&str],
    input: &[u8],
    stdout: File,
    stdout_limit: u64,
    label: &str,
) -> Result<Output> {
    control
        .remaining_until(deadline, MATERIALIZATION_LABEL)?
        .run_git_with_input_to_file(cwd, args, input, stdout, stdout_limit, label)
}

fn ensure_git_success(output: &Output, action: &str) -> Result<()> {
    anyhow::ensure!(
        output.status.success(),
        "patch:finding could not {action}: {}",
        command_output_text(output)
    );
    Ok(())
}
