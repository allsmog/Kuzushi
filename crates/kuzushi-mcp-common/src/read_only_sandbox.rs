mod backend;
mod probe;

#[cfg(test)]
mod tests;

use anyhow::{Context, Result};
use std::ffi::OsStr;
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
    pub(super) input: crate::AuthorizedDirectory,
    pub(super) scratch: TempDir,
    pub(super) _retained_handles: Vec<File>,
}

impl SandboxedCommand {
    pub fn command_mut(&mut self) -> Result<&mut Command> {
        self.input.verify_unchanged()?;
        Ok(&mut self.command)
    }

    pub fn spawn(mut self, label: &str) -> Result<(Child, TempDir)> {
        self.input.verify_unchanged()?;
        configure_long_lived_group(&mut self.command);
        let child = self
            .command
            .spawn()
            .with_context(|| format!("could not start sandboxed {label}"))?;
        Ok((child, self.scratch))
    }
}

pub async fn sandbox_available() -> bool {
    verified_backend().await.is_ok()
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
