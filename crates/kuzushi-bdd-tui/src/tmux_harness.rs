//! Thin wrapper around the `tmux` CLI that lets a BDD scenario boot a
//! real `kuzushi shell` binary, send keys to it, and capture the
//! rendered pane contents. Sessions are torn down on `Drop` so a test
//! panic never leaves a hung tmux session behind.

use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

/// Owned tmux session that runs the shell under test. Drop kills the
/// session even if the test panics partway.
#[derive(Debug)]
pub struct TmuxSession {
    pub session_name: String,
    pub target: PathBuf,
    pub home: PathBuf,
    _temp_home: tempfile::TempDir,
    _temp_target: tempfile::TempDir,
}

/// Pre-launch seed instructions applied to the scenario's target dir
/// before the shell binary starts. `File(path, body)` writes a file;
/// `Dir(path, placeholder)` creates a directory and writes one file
/// inside it so artifact-state probes recognize it as `Cached`.
#[derive(Debug, Clone)]
pub enum ArtifactSeed {
    File { relative: String, body: String },
    Dir { relative: String, placeholder: String },
}

impl TmuxSession {
    /// Spin up a tmux session running `binary shell --target <tempdir>`
    /// with `HOME` redirected to a tempdir so OAuth / config writes
    /// stay scoped to this scenario.
    pub fn launch(binary: &str, env: HashMap<String, String>) -> Result<Self> {
        Self::launch_with_seeds(binary, env, &[])
    }

    pub fn launch_with_seeds(
        binary: &str,
        env: HashMap<String, String>,
        seeds: &[ArtifactSeed],
    ) -> Result<Self> {
        require_tmux()?;
        let session_name = format!("kbdd-{}", uuid::Uuid::new_v4().simple());
        let temp_home = tempfile::tempdir().context("creating scoped HOME")?;
        let temp_target = tempfile::tempdir().context("creating scoped target")?;
        write_v2_config_from_env(temp_home.path(), &env)?;
        seed_target(temp_target.path())?;
        apply_artifact_seeds(temp_target.path(), seeds)?;

        let mut cmd = format!(
            "HOME={home} ",
            home = shell_escape(temp_home.path().to_string_lossy().as_ref()),
        );
        for (key, value) in &env {
            if matches!(key.as_str(), "HOME" | "KUZUSHI_V2_CONFIG_MODEL") {
                continue;
            }
            cmd.push_str(&format!("{key}={} ", shell_escape(value)));
        }
        cmd.push_str(&format!(
            "{bin} shell --target {target}",
            bin = shell_escape(binary),
            target = shell_escape(temp_target.path().to_string_lossy().as_ref()),
        ));

        let status = Command::new("tmux")
            .args([
                "new-session",
                "-d",
                "-s",
                &session_name,
                "-x",
                "200",
                "-y",
                "50",
                &cmd,
            ])
            .status()
            .context("invoking tmux new-session")?;
        if !status.success() {
            bail!("tmux new-session exited with status {:?}", status.code());
        }
        Ok(Self {
            session_name,
            target: temp_target.path().to_path_buf(),
            home: temp_home.path().to_path_buf(),
            _temp_home: temp_home,
            _temp_target: temp_target,
        })
    }

    /// Forward keyboard input to the session. `keys` follows the tmux
    /// send-keys vocabulary — e.g. `"Down"`, `"Enter"`, `"Space"`,
    /// `"Escape"`, or a literal string.
    pub fn send_keys(&self, keys: &[&str]) -> Result<()> {
        for key in keys {
            let status = Command::new("tmux")
                .args(["send-keys", "-t", &self.session_name, key])
                .status()
                .context("invoking tmux send-keys")?;
            if !status.success() {
                bail!(
                    "tmux send-keys '{key}' returned status {:?}",
                    status.code()
                );
            }
        }
        Ok(())
    }

    pub fn snapshot(&self) -> Result<String> {
        let output = Command::new("tmux")
            .args(["capture-pane", "-t", &self.session_name, "-p", "-S", "-200"])
            .output()
            .context("invoking tmux capture-pane")?;
        if !output.status.success() {
            bail!(
                "tmux capture-pane returned status {:?}",
                output.status.code()
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Poll the pane up to `timeout` waiting for `needle` to appear.
    pub fn wait_for(&self, needle: &str, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            let snapshot = self.snapshot()?;
            if snapshot.contains(needle) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!(
                    "timed out after {:?} waiting for `{needle}` in pane:\n{snapshot}",
                    timeout
                );
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for TmuxSession {
    fn drop(&mut self) {
        let _ = Command::new("tmux")
            .args(["kill-session", "-t", &self.session_name])
            .status();
    }
}

fn require_tmux() -> Result<()> {
    let status = Command::new("tmux")
        .arg("-V")
        .status()
        .context("tmux not on PATH — install it to run BDD scenarios")?;
    if !status.success() {
        bail!("`tmux -V` returned {:?}", status.code());
    }
    Ok(())
}

fn shell_escape(value: &str) -> String {
    if value.is_empty()
        || value
            .chars()
            .any(|c| !c.is_ascii_alphanumeric() && !matches!(c, '/' | '.' | '_' | '-' | '+' | ':'))
    {
        format!("'{}'", value.replace('\'', "'\\''"))
    } else {
        value.to_string()
    }
}

fn write_v2_config_from_env(home: &std::path::Path, env: &HashMap<String, String>) -> Result<()> {
    let Some(model) = env.get("KUZUSHI_V2_CONFIG_MODEL") else {
        return Ok(());
    };
    let dir = home.join(".kuzushi/v2");
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating {} for scoped v2 config", dir.display()))?;
    let path = dir.join("config.toml");
    std::fs::write(&path, format!("model = \"{model}\"\n"))
        .with_context(|| format!("writing {} for scoped v2 config", path.display()))?;
    Ok(())
}

fn seed_target(target: &std::path::Path) -> Result<()> {
    std::fs::write(
        target.join("package.json"),
        r#"{"name":"bdd-target","version":"1.0.0","dependencies":{"express":"4.18.2"}}"#,
    )
    .context("seeding package.json into BDD target")?;
    Ok(())
}

fn apply_artifact_seeds(target: &std::path::Path, seeds: &[ArtifactSeed]) -> Result<()> {
    for seed in seeds {
        match seed {
            ArtifactSeed::File { relative, body } => {
                let path = target.join(relative);
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("creating parent dir for {}", path.display()))?;
                }
                std::fs::write(&path, body)
                    .with_context(|| format!("seeding file {}", path.display()))?;
            }
            ArtifactSeed::Dir { relative, placeholder } => {
                let dir = target.join(relative);
                std::fs::create_dir_all(&dir)
                    .with_context(|| format!("seeding directory {}", dir.display()))?;
                std::fs::write(dir.join("placeholder"), placeholder)
                    .with_context(|| format!("seeding placeholder in {}", dir.display()))?;
            }
        }
    }
    Ok(())
}
