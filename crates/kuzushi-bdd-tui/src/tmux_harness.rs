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
    File {
        relative: String,
        body: String,
    },
    Dir {
        relative: String,
        placeholder: String,
    },
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
        Self::launch_inner(binary, env, seeds, true, (200, 50))
    }

    /// Launch a bare interactive `kuzushi shell` with **no** `--target`, from a
    /// scoped temp directory. Exercises the launch-time target-picker gate,
    /// which only fires when the operator supplied no target.
    pub fn launch_targetless(binary: &str, env: HashMap<String, String>) -> Result<Self> {
        Self::launch_inner(binary, env, &[], false, (200, 50))
    }

    pub fn launch_targetless_sized(
        binary: &str,
        env: HashMap<String, String>,
        size: (u16, u16),
    ) -> Result<Self> {
        Self::launch_inner(binary, env, &[], false, size)
    }

    fn launch_inner(
        binary: &str,
        env: HashMap<String, String>,
        seeds: &[ArtifactSeed],
        with_target: bool,
        (width, height): (u16, u16),
    ) -> Result<Self> {
        require_tmux()?;
        let session_name = format!("kbdd-{}", uuid::Uuid::new_v4().simple());
        let (temp_home, temp_target, session_tmp) = prepare_scenario_workspace(&env, seeds)?;
        let cmd = launch_command(
            binary,
            &env,
            with_target,
            temp_home.path(),
            temp_target.path(),
            &session_tmp,
        );
        start_tmux_session(&session_name, (width, height), &cmd)?;
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
                bail!("tmux send-keys '{key}' returned status {:?}", status.code());
            }
        }
        Ok(())
    }

    pub fn send_literal(&self, value: &str) -> Result<()> {
        let status = Command::new("tmux")
            .args(["send-keys", "-l", "-t", &self.session_name, "--", value])
            .status()
            .context("invoking tmux send-keys -l")?;
        if !status.success() {
            bail!("tmux send-keys literal returned status {:?}", status.code());
        }
        Ok(())
    }

    pub fn snapshot(&self) -> Result<String> {
        let output = if self.alternate_screen_active()? {
            self.capture_pane(&["-p"])?
        } else {
            let saved = self.capture_pane(&["-a", "-q", "-p"])?;
            if saved.status.success() && output_has_visible_text(&saved.stdout) {
                saved
            } else {
                self.capture_pane(&["-p", "-S", "-200"])?
            }
        };
        if !output.status.success() {
            bail!(
                "tmux capture-pane returned status {:?}",
                output.status.code()
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn alternate_screen_active(&self) -> Result<bool> {
        let output = Command::new("tmux")
            .args([
                "display-message",
                "-p",
                "-t",
                &self.session_name,
                "#{alternate_on}",
            ])
            .output()
            .context("checking tmux alternate screen state")?;
        Ok(output.status.success() && output.stdout.starts_with(b"1"))
    }

    fn capture_pane(&self, options: &[&str]) -> Result<std::process::Output> {
        let mut command = Command::new("tmux");
        command.args(["capture-pane", "-t", &self.session_name]);
        command.args(options);
        command.output().context("invoking tmux capture-pane")
    }

    pub fn wait_for_status_segment(&self, needle: &str, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            let snapshot = self.snapshot()?;
            if status_footer_line(&snapshot).is_some_and(|line| line.contains(needle)) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                let status = status_footer_line(&snapshot).unwrap_or("<not rendered>");
                bail!(
                    "timed out after {:?} waiting for status segment `{needle}`; footer was `{status}`\ncurrent pane:\n{snapshot}",
                    timeout
                );
            }
            thread::sleep(Duration::from_millis(100));
        }
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

fn prepare_scenario_workspace(
    env: &HashMap<String, String>,
    seeds: &[ArtifactSeed],
) -> Result<(tempfile::TempDir, tempfile::TempDir, PathBuf)> {
    let temp_home = tempfile::tempdir().context("creating scoped HOME")?;
    let temp_target = tempfile::tempdir().context("creating scoped target")?;
    write_v2_config_from_env(temp_home.path(), env)?;
    seed_target(temp_target.path())?;
    apply_artifact_seeds(temp_target.path(), seeds)?;
    let session_tmp = temp_home.path().join("tmp");
    std::fs::create_dir_all(&session_tmp).context("creating scenario TMPDIR")?;
    Ok((temp_home, temp_target, session_tmp))
}

fn launch_command(
    binary: &str,
    env: &HashMap<String, String>,
    with_target: bool,
    home: &std::path::Path,
    target: &std::path::Path,
    session_tmp: &std::path::Path,
) -> String {
    let mut cmd = targetless_working_directory(with_target, target);
    append_isolated_environment(&mut cmd, home, session_tmp, env);
    append_requested_environment(&mut cmd, env);
    cmd.push_str(&shell_invocation(binary, with_target, target));
    cmd
}

fn targetless_working_directory(with_target: bool, target: &std::path::Path) -> String {
    if with_target {
        return String::new();
    }
    format!(
        "cd {dir} && ",
        dir = shell_escape(target.to_string_lossy().as_ref())
    )
}

fn append_requested_environment(cmd: &mut String, env: &HashMap<String, String>) {
    for (key, value) in env.iter().filter(|(key, _)| !is_harness_owned_env(key)) {
        cmd.push_str(&format!("{key}={} ", shell_escape(value)));
    }
}

fn shell_invocation(binary: &str, with_target: bool, target: &std::path::Path) -> String {
    let binary = shell_escape(binary);
    if with_target {
        return format!(
            "{binary} shell --target {target}",
            target = shell_escape(target.to_string_lossy().as_ref())
        );
    }
    format!("{binary} shell")
}

fn start_tmux_session(session_name: &str, (width, height): (u16, u16), cmd: &str) -> Result<()> {
    let width = width.to_string();
    let height = height.to_string();
    let status = Command::new("tmux")
        .args([
            "new-session",
            "-d",
            "-s",
            session_name,
            "-x",
            &width,
            "-y",
            &height,
            cmd,
        ])
        .status()
        .context("invoking tmux new-session")?;
    if !status.success() {
        bail!("tmux new-session exited with status {:?}", status.code());
    }
    Ok(())
}

fn append_isolated_environment(
    cmd: &mut String,
    home: &std::path::Path,
    session_tmp: &std::path::Path,
    env: &HashMap<String, String>,
) {
    let path = env
        .get("PATH")
        .cloned()
        .or_else(|| std::env::var("PATH").ok())
        .unwrap_or_else(|| "/usr/bin:/bin".to_string());
    let term = env
        .get("TERM")
        .map(String::as_str)
        .unwrap_or("xterm-256color");
    cmd.push_str("env -i ");
    for (key, value) in [
        ("HOME", home.to_string_lossy().into_owned()),
        ("TMPDIR", session_tmp.to_string_lossy().into_owned()),
        ("PATH", path),
        ("TERM", term.to_string()),
        ("LANG", "C.UTF-8".to_string()),
    ] {
        cmd.push_str(&format!("{key}={} ", shell_escape(&value)));
    }
}

fn is_harness_owned_env(key: &str) -> bool {
    matches!(
        key,
        "HOME" | "TMPDIR" | "PATH" | "TERM" | "LANG" | "KUZUSHI_V2_CONFIG_MODEL"
    )
}

fn status_footer_line(snapshot: &str) -> Option<&str> {
    snapshot
        .lines()
        .rev()
        .take(8)
        .find(|line| line.contains("mode:"))
}

fn output_has_visible_text(bytes: &[u8]) -> bool {
    bytes.iter().any(|byte| !byte.is_ascii_whitespace())
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
    let dir = home.join(".kuzushi/v3");
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
            ArtifactSeed::Dir {
                relative,
                placeholder,
            } => {
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
