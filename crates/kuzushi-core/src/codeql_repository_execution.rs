use crate::remediation::patch::{
    verify_repository_source_binding, with_disposable_repository_target, RepositorySourceBinding,
};
use crate::remediation::patch_process_adapter::PatchProcessControl as PatchCommandControl;
use anyhow::{Context, Result};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

mod launcher;
mod promotion;
mod provenance;

pub(crate) use launcher::{
    bind_codeql_launcher, prepared_codeql_launcher, verify_codeql_launcher, PreparedCodeqlLauncher,
};
pub(crate) use promotion::codeql_database_is_valid;
use promotion::{inspect_destination, promote_database, DestinationState};
#[cfg(test)]
pub(crate) use provenance::write_test_codeql_database_provenance;
pub(crate) use provenance::{resolve_managed_codeql_database, ValidatedManagedCodeqlDatabase};

pub(crate) const DEFAULT_CODEQL_REPOSITORY_TIMEOUT_MS: u64 = 30 * 60 * 1000;
pub(crate) const MAX_CODEQL_REPOSITORY_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1000;

pub(crate) fn managed_codeql_analysis_safety_args(log_dir: &Path) -> [String; 4] {
    [
        "--rerun".to_string(),
        "--max-disk-cache=0".to_string(),
        "--expect-discarded-cache".to_string(),
        format!("--logdir={}", log_dir.display()),
    ]
}

#[derive(Clone, Copy)]
pub(crate) enum CodeqlBuildStrategy<'a> {
    BuildMode(&'a str),
    Manual(&'a str),
}

pub(crate) struct CodeqlRepositoryRequest<'a> {
    pub source_root: &'a Path,
    pub binding: RepositorySourceBinding,
    pub destination: &'a Path,
    pub launcher: PreparedCodeqlLauncher,
    pub cancellation: Option<&'a crate::scan::ScanCancellation>,
    pub timeout: Duration,
}

/// Holds the destination lock and source binding across planning, extraction,
/// validation, and publication of one managed CodeQL database.
pub(crate) struct CodeqlRepositoryExecution<'a> {
    request: CodeqlRepositoryRequest<'a>,
    relative_database: PathBuf,
    destination_state: DestinationState,
    _destination_lock: crate::file_lock::ExclusiveFileLock,
}

impl<'a> CodeqlRepositoryExecution<'a> {
    pub(crate) fn prepare(request: CodeqlRepositoryRequest<'a>) -> Result<Self> {
        let relative_database =
            validated_database_relative(request.source_root, request.destination)?;
        let lock_path = destination_lock_path(request.source_root, &relative_database)?;
        let destination_lock = crate::file_lock::ExclusiveFileLock::acquire(&lock_path)?;
        let control = PatchCommandControl::new(request.cancellation, request.timeout);
        verify_repository_source_binding(request.source_root, &request.binding, control)?;
        let destination_state = inspect_destination(request.destination)?;
        Ok(Self {
            request,
            relative_database,
            destination_state,
            _destination_lock: destination_lock,
        })
    }

    pub(crate) fn with_bound_target<T>(
        &self,
        operation: impl FnOnce(&Path) -> Result<T>,
    ) -> Result<T> {
        with_disposable_repository_target(
            self.request.source_root,
            &self.request.binding,
            self.control(),
            operation,
        )
    }

    pub(crate) fn build(
        &self,
        checkout_target: &Path,
        language: &str,
        strategy: CodeqlBuildStrategy<'_>,
    ) -> Result<Output> {
        let isolated_db = crate::workspace::prepare_workspace_output_path(
            checkout_target,
            &self.relative_database,
        )?;
        let launcher = self
            .request
            .launcher
            .resolve_for_checkout(
                self.request.source_root,
                &self.request.binding,
                checkout_target,
            )?
            .context("CodeQL launcher was unavailable when the operation was prepared")?;
        let args = codeql_arguments(&self.relative_database, language, strategy, checkout_target)?;
        let output = self.control().run_program(
            checkout_target,
            launcher.path(),
            launcher.read_scope(),
            &args,
            "isolated CodeQL database build",
        )?;
        if output.status.success() {
            self.publish_successful_build(&isolated_db, language)?;
        }
        Ok(output)
    }

    fn publish_successful_build(&self, isolated_db: &Path, language: &str) -> Result<()> {
        anyhow::ensure!(
            promotion::codeql_database_has_shape(isolated_db),
            "CodeQL reported success without a complete database in the isolated checkout"
        );
        let provenance = provenance::write_codeql_database_provenance(
            isolated_db,
            &self.request.binding,
            language,
        )?;
        let database_identity = promote_database(
            self.request.source_root,
            isolated_db,
            self.request.destination,
            self.destination_state.clone(),
        )?;
        provenance::write_codeql_promotion_receipt(
            self.request.source_root,
            &provenance,
            &database_identity,
        )
    }

    fn control(&self) -> PatchCommandControl<'a> {
        PatchCommandControl::new(self.request.cancellation, self.request.timeout)
    }
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

fn validated_database_relative(source_root: &Path, destination: &Path) -> Result<PathBuf> {
    let canonical_source_root = fs::canonicalize(source_root)
        .with_context(|| format!("could not resolve source root {}", source_root.display()))?;
    let relative = destination
        .strip_prefix(source_root)
        .or_else(|_| destination.strip_prefix(&canonical_source_root))
        .with_context(|| {
            format!(
                "CodeQL database output {} must stay inside target {}",
                destination.display(),
                canonical_source_root.display()
            )
        })?;
    anyhow::ensure!(
        relative.starts_with(crate::workspace::KUZUSHI_STATE_DIR),
        "CodeQL database output {} must stay below .kuzushi",
        destination.display()
    );
    crate::workspace::prepare_workspace_output_path(&canonical_source_root, relative)?;
    Ok(relative.to_path_buf())
}

fn destination_lock_path(source_root: &Path, database_relative: &Path) -> Result<PathBuf> {
    let parent = database_relative
        .parent()
        .context("CodeQL database output has no parent")?;
    let name = database_relative
        .file_name()
        .and_then(|name| name.to_str())
        .context("CodeQL database output name is not UTF-8")?;
    let relative = parent.join(format!(".{name}.lock"));
    crate::workspace::prepare_workspace_output_path(source_root, &relative)
}

fn acquire_managed_database_lock(
    source_root: &Path,
    destination: &Path,
) -> Result<crate::file_lock::ExclusiveFileLock> {
    let relative = validated_database_relative(source_root, destination)?;
    let lock_path = destination_lock_path(source_root, &relative)?;
    crate::file_lock::ExclusiveFileLock::acquire(&lock_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_analysis_args_disable_database_side_caches_and_logs() {
        let args = managed_codeql_analysis_safety_args(Path::new("/tmp/codeql-logs"));

        assert!(args.iter().any(|arg| arg == "--rerun"));
        assert!(args.iter().any(|arg| arg == "--max-disk-cache=0"));
        assert!(args.iter().any(|arg| arg == "--expect-discarded-cache"));
        assert!(args.iter().any(|arg| arg == "--logdir=/tmp/codeql-logs"));
    }

    #[test]
    fn prepared_execution_owns_the_cross_process_destination_lock() {
        let repository = tempfile::tempdir().unwrap();
        run_git(repository.path(), &["init", "-q"]);
        std::fs::write(repository.path().join("source.js"), "const value = 1;\n").unwrap();
        std::fs::write(repository.path().join("codeql"), "test launcher\n").unwrap();
        run_git(repository.path(), &["add", "source.js", "codeql"]);
        run_git(repository.path(), &["commit", "-qm", "initial"]);
        crate::workspace::initialize_workspace_state(repository.path()).unwrap();
        let binding = crate::remediation::patch::clean_repository_source_binding(
            repository.path(),
            crate::remediation::patch::unattended_patch_control(),
        )
        .unwrap();
        let destination = crate::workspace::workspace_codeql_db_path(repository.path());
        let execution = CodeqlRepositoryExecution::prepare(CodeqlRepositoryRequest {
            source_root: repository.path(),
            binding,
            destination: &destination,
            launcher: PreparedCodeqlLauncher::Unavailable,
            cancellation: None,
            timeout: Duration::from_secs(5),
        })
        .unwrap();
        let relative = validated_database_relative(repository.path(), &destination).unwrap();
        let lock = destination_lock_path(repository.path(), &relative).unwrap();

        assert!(crate::file_lock::ExclusiveFileLock::try_acquire(&lock)
            .unwrap()
            .is_none());
        drop(execution);
        assert!(crate::file_lock::ExclusiveFileLock::try_acquire(&lock)
            .unwrap()
            .is_some());
    }

    fn run_git(repository: &Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .args(["-c", "user.email=test@example.invalid"])
            .args(["-c", "user.name=Kuzushi Test"])
            .args(args)
            .current_dir(repository)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }
}
