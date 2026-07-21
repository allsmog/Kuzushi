use crate::config::RemoteBox;
use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

/// The only seam that touches the network. Everything above it is pure and
/// unit-tested against fakes.
pub trait Transport {
    fn run(&self, remote: &RemoteBox, command: &str) -> Result<CommandOutput>;
    fn push(&self, remote: &RemoteBox, local: &Path, remote_path: &str) -> Result<()>;
    fn pull(&self, remote: &RemoteBox, remote_path: &str, local: &Path) -> Result<()>;
}

pub struct SshTransport;

impl Transport for SshTransport {
    fn run(&self, remote: &RemoteBox, command: &str) -> Result<CommandOutput> {
        let output = Command::new("ssh")
            .args(["-o", "BatchMode=yes", &remote.ssh, command])
            .output()
            .with_context(|| format!("failed to run ssh to {}", remote.name))?;
        Ok(CommandOutput {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    /// Loud-fail by contract: a non-zero scp is an error with stderr
    /// attached, never a warning. A silent transfer failure once re-ran a
    /// stale queue.
    fn push(&self, remote: &RemoteBox, local: &Path, remote_path: &str) -> Result<()> {
        scp(
            &local.display().to_string(),
            &format!("{}:{}", remote.ssh, remote_path),
        )
    }

    fn pull(&self, remote: &RemoteBox, remote_path: &str, local: &Path) -> Result<()> {
        scp(
            &format!("{}:{}", remote.ssh, remote_path),
            &local.display().to_string(),
        )
    }
}

fn scp(from: &str, to: &str) -> Result<()> {
    let output = Command::new("scp")
        .args(["-o", "BatchMode=yes", "-r", from, to])
        .output()
        .context("failed to run scp")?;
    anyhow::ensure!(
        output.status.success(),
        "scp {from} -> {to} failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}
