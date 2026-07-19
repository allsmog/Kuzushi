mod backend;
mod probe;

#[cfg(test)]
mod tests;

use anyhow::{Context, Result};
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs::File;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use tokio::process::{Child, Command};
use tokio::sync::OnceCell;

static VERIFIED_BACKEND: OnceCell<Option<ReadOnlySandboxBackend>> = OnceCell::const_new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadOnlySandboxBackend {
    MacosSeatbelt,
    LinuxBubblewrap,
}

pub struct SandboxedCommand {
    pub(super) command: Command,
    pub(super) protected: Vec<crate::AuthorizedDirectory>,
    pub(super) scratch: TempDir,
    pub(super) _retained_handles: Vec<File>,
}

impl SandboxedCommand {
    pub fn command_mut(&mut self) -> Result<&mut Command> {
        verify_directories(&self.protected)?;
        Ok(&mut self.command)
    }

    pub fn spawn(mut self, label: &str) -> Result<(Child, TempDir)> {
        verify_directories(&self.protected)?;
        configure_long_lived_group(&mut self.command);
        let child = self
            .command
            .spawn()
            .with_context(|| format!("could not start sandboxed {label}"))?;
        Ok((child, self.scratch))
    }
}

/// Explicit filesystem authority for a sandboxed tool invocation.
///
/// All read-only and read-write roots retain no-follow directory handles until
/// after the child is spawned. The executable bundle is deliberately separate
/// from the working input because tools such as CodeQL load siblings of their
/// launcher at runtime.
pub struct RestrictedSandboxAccess {
    pub working_directory: crate::AuthorizedDirectory,
    pub tool_root: crate::AuthorizedDirectory,
    pub read_only: Vec<crate::AuthorizedDirectory>,
    pub read_write: Vec<crate::AuthorizedDirectory>,
    /// A bounded, deny-by-default set of adapter-approved child variables.
    pub environment: Vec<(OsString, OsString)>,
}

pub async fn sandbox_available() -> bool {
    verified_backend().await.is_ok()
}

pub async fn terminate_child_group(child: &mut Child) {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        // SAFETY: sandbox children are placed in a dedicated process group
        // whose id is the launcher pid before spawn returns.
        unsafe { libc::killpg(pid as libc::pid_t, libc::SIGKILL) };
    }
    #[cfg(not(unix))]
    let _ = child.kill().await;
    let _ = child.wait().await;
}

pub async fn read_only_command<I, S>(
    program: &Path,
    args: I,
    input: crate::AuthorizedDirectory,
) -> Result<SandboxedCommand>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let backend = verified_backend().await?;
    backend::build_command(backend, program, args, input)
}

pub async fn restricted_command<I, S>(
    program: &Path,
    args: I,
    access: RestrictedSandboxAccess,
) -> Result<SandboxedCommand>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let backend = verified_backend().await?;
    backend::build_restricted_command(backend, program, args, access)
}

fn verify_directories(directories: &[crate::AuthorizedDirectory]) -> Result<()> {
    directories
        .iter()
        .try_for_each(crate::AuthorizedDirectory::verify_unchanged)
}

pub fn resolve_regular_executable(program: &OsStr) -> Result<PathBuf> {
    let requested = Path::new(program);
    let candidate = if requested.components().count() > 1 {
        requested.to_path_buf()
    } else {
        crate::doctor::which(requested.to_string_lossy().as_ref())
            .with_context(|| format!("executable is not on PATH: {}", requested.display()))?
    };
    let canonical = std::fs::canonicalize(&candidate)
        .with_context(|| format!("could not canonicalize executable: {}", candidate.display()))?;
    let metadata = canonical
        .metadata()
        .with_context(|| format!("could not inspect executable: {}", canonical.display()))?;
    anyhow::ensure!(
        metadata.is_file(),
        "executable is not a regular file: {}",
        canonical.display()
    );
    ensure_executable_mode(&canonical, &metadata)?;
    Ok(canonical)
}

async fn verified_backend() -> Result<ReadOnlySandboxBackend> {
    VERIFIED_BACKEND
        .get_or_init(|| async { probe::self_probe_candidate().await })
        .await
        .context("no supported read-only MCP sandbox passed its self-probe")
}

fn configure_long_lived_group(command: &mut Command) {
    command.kill_on_drop(true);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.as_std_mut().process_group(0);
    }
}

#[cfg(unix)]
fn ensure_executable_mode(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    anyhow::ensure!(
        metadata.permissions().mode() & 0o111 != 0,
        "executable has no execute bit: {}",
        path.display()
    );
    Ok(())
}

#[cfg(not(unix))]
fn ensure_executable_mode(_path: &Path, _metadata: &std::fs::Metadata) -> Result<()> {
    Ok(())
}
