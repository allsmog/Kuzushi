use anyhow::{Context, Result};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

#[derive(Clone, Copy)]
pub(crate) struct PatchProcessControl<'a> {
    cancellation: Option<&'a crate::scan::ScanCancellation>,
    timeout: Duration,
}

impl<'a> PatchProcessControl<'a> {
    pub(crate) fn new(
        cancellation: Option<&'a crate::scan::ScanCancellation>,
        timeout: Duration,
    ) -> Self {
        Self {
            cancellation,
            timeout,
        }
    }

    pub(crate) fn unattended(timeout: Duration) -> Self {
        Self::new(None, timeout)
    }

    pub(crate) fn cleanup(self) -> Self {
        Self::new(None, self.timeout)
    }

    pub(crate) fn ensure_active(self) -> Result<()> {
        if self
            .cancellation
            .is_some_and(crate::scan::ScanCancellation::is_cancelled)
        {
            anyhow::bail!("patch validation was cancelled")
        }
        Ok(())
    }

    pub(crate) fn run_git(self, cwd: &Path, args: &[&str], label: &str) -> Result<Output> {
        self.ensure_active()?;
        let mut command = Command::new("git");
        command.args(args).current_dir(cwd).stdin(Stdio::null());
        self.output(&mut command, label)
    }

    pub(crate) fn run_git_with_input(
        self,
        cwd: &Path,
        args: &[&str],
        input: &[u8],
        label: &str,
    ) -> Result<Output> {
        self.ensure_active()?;
        let mut command = Command::new("git");
        command.args(args).current_dir(cwd);
        crate::bounded_subprocess::output_with_input_and_control(
            &mut command,
            label,
            input.to_vec(),
            self.cancellation,
            self.timeout,
        )
    }

    pub(crate) fn run_shell(self, cwd: &Path, script: &str, label: &str) -> Result<Output> {
        self.ensure_active()?;
        let mut command = Command::new("sh");
        command
            .args(["-lc", script])
            .current_dir(cwd)
            .stdin(Stdio::null());
        self.output(&mut command, label)
    }

    fn output(self, command: &mut Command, label: &str) -> Result<Output> {
        crate::bounded_subprocess::output_with_control(
            command,
            label,
            self.cancellation,
            self.timeout,
        )
        .with_context(|| format!("{label} subprocess failed"))
    }
}
