use anyhow::{Context, Result};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

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

    pub(crate) fn ensure_active(self) -> Result<()> {
        if self
            .cancellation
            .is_some_and(crate::scan::ScanCancellation::is_cancelled)
        {
            anyhow::bail!("patch validation was cancelled")
        }
        Ok(())
    }

    pub(crate) fn deadline(self, label: &str) -> Result<Instant> {
        self.ensure_active()?;
        Instant::now()
            .checked_add(self.timeout)
            .with_context(|| format!("{label} deadline is outside the supported clock range"))
    }

    pub(crate) fn remaining_until(self, deadline: Instant, label: &str) -> Result<Self> {
        self.ensure_active()?;
        let timeout = deadline.saturating_duration_since(Instant::now());
        anyhow::ensure!(!timeout.is_zero(), "{label} exceeded its deadline");
        Ok(Self {
            cancellation: self.cancellation,
            timeout,
        })
    }

    pub(crate) fn run_git(self, cwd: &Path, args: &[&str], label: &str) -> Result<Output> {
        self.ensure_active()?;
        let mut command = Command::new("git");
        configure_safe_git_command(&mut command);
        command.args(args).current_dir(cwd).stdin(Stdio::null());
        configure_minimal_environment(&mut command, cwd);
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
        configure_safe_git_command(&mut command);
        command.args(args).current_dir(cwd);
        configure_minimal_environment(&mut command, cwd);
        crate::bounded_subprocess::output_with_input_and_control(
            &mut command,
            label,
            input.to_vec(),
            self.cancellation,
            self.timeout,
        )
    }

    pub(crate) fn run_git_with_input_to_file(
        self,
        cwd: &Path,
        args: &[&str],
        input: &[u8],
        stdout: File,
        stdout_limit: u64,
        label: &str,
    ) -> Result<Output> {
        self.ensure_active()?;
        let mut command = Command::new("git");
        configure_safe_git_command(&mut command);
        command.args(args).current_dir(cwd);
        configure_minimal_environment(&mut command, cwd);
        crate::bounded_subprocess::output_with_input_to_file_and_control(
            &mut command,
            label,
            input.to_vec(),
            stdout,
            stdout_limit,
            self.cancellation,
            self.timeout,
        )
    }

    pub(crate) fn run_shell(self, cwd: &Path, script: &str, label: &str) -> Result<Output> {
        self.ensure_active()?;
        let mut command = validation_shell_command(cwd, script)?;
        command.current_dir(cwd).stdin(Stdio::null());
        configure_validation_environment(&mut command, cwd)?;
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

pub(crate) fn patch_network_isolation_disclosure() -> &'static str {
    if validation_network_sandbox_available() {
        "network denied; operator credential files and writes outside the validation checkout denied; toolchain and dependency-cache reads allowlisted by the host sandbox"
    } else {
        "validation commands fail closed because no isolating host sandbox is available"
    }
}

fn validation_shell_command(_cwd: &Path, script: &str) -> Result<Command> {
    #[cfg(target_os = "macos")]
    if Path::new("/usr/bin/sandbox-exec").is_file() {
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command.args([
            "-p",
            &macos_validation_profile(_cwd),
            "/bin/sh",
            "-c",
            script,
        ]);
        return Ok(command);
    }
    #[cfg(target_os = "linux")]
    if kuzushi_sandbox::which("bwrap").is_some() {
        return Ok(linux_validation_command(_cwd, script));
    }
    anyhow::bail!("patch validation refused: no isolating sandbox is available on this host")
}

#[cfg(target_os = "macos")]
fn macos_validation_profile(cwd: &Path) -> String {
    let canonical_cwd = std::fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    let home = dirs::home_dir();
    let mut profile = String::from("(version 1)(allow default)(deny network*)");
    if let Some(home) = home.as_deref() {
        profile.push_str(&format!(
            "(deny file-read* (subpath \"{}\"))",
            sandbox_literal(home)
        ));
    }
    profile.push_str("(deny file-read* (subpath \"/Volumes\"))");
    for path in validation_read_paths(&canonical_cwd) {
        profile.push_str(&format!(
            "(allow file-read* (subpath \"{}\"))",
            sandbox_literal(&path)
        ));
    }
    profile.push_str("(deny file-write*)");
    for path in [
        canonical_cwd.clone(),
        validation_state_root(&canonical_cwd),
        PathBuf::from("/dev"),
    ] {
        profile.push_str(&format!(
            "(allow file-write* (subpath \"{}\"))",
            sandbox_literal(&path)
        ));
    }
    profile
}

#[cfg(target_os = "macos")]
fn sandbox_literal(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

#[cfg(target_os = "linux")]
fn linux_validation_command(cwd: &Path, script: &str) -> Command {
    let mut command = Command::new("bwrap");
    command.args([
        "--die-with-parent",
        "--unshare-all",
        "--cap-drop",
        "ALL",
        "--new-session",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/tooling",
    ]);
    append_linux_system_mounts(&mut command);
    append_linux_toolchain_mounts(&mut command);
    command
        .args(["--dir", "/work", "--bind"])
        .arg(cwd)
        .args(["/work", "--chdir", "/work"]);
    append_linux_child_environment(&mut command);
    command.args(["--", "/bin/sh", "-c", script]);
    command
}

#[cfg(target_os = "linux")]
fn append_linux_system_mounts(command: &mut Command) {
    for path in [
        "/usr",
        "/usr/local",
        "/lib",
        "/lib64",
        "/bin",
        "/sbin",
        "/opt",
        "/etc/alternatives",
        "/etc/ssl",
    ] {
        let path = Path::new(path);
        if path.exists() {
            command.arg("--ro-bind").arg(path).arg(path);
        }
    }
}

#[cfg(target_os = "linux")]
fn append_linux_toolchain_mounts(command: &mut Command) {
    command.args(["--dir", "/tooling/cargo"]);
    append_linux_cargo_mounts(command);
    append_linux_rustup_mount(command);
}

#[cfg(target_os = "linux")]
fn append_linux_cargo_mounts(command: &mut Command) {
    if let Some(cargo_home) = cargo_home() {
        for leaf in ["bin", "registry"] {
            let host = cargo_home.join(leaf);
            if host.exists() {
                command
                    .arg("--ro-bind")
                    .arg(host)
                    .arg(format!("/tooling/cargo/{leaf}"));
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn append_linux_rustup_mount(command: &mut Command) {
    if let Some(rustup_home) = rustup_home().filter(|path| path.exists()) {
        command
            .args(["--ro-bind"])
            .arg(rustup_home)
            .arg("/tooling/rustup");
    }
}

#[cfg(target_os = "linux")]
fn append_linux_child_environment(command: &mut Command) {
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".into());
    command.args([
        "--setenv",
        "PATH",
        &format!("/tooling/cargo/bin:{path}"),
        "--setenv",
        "HOME",
        "/work/.kuzushi-validation/home",
        "--setenv",
        "CARGO_HOME",
        "/tooling/cargo",
        "--setenv",
        "RUSTUP_HOME",
        "/tooling/rustup",
        "--setenv",
        "TMPDIR",
        "/tmp",
    ]);
}

pub(crate) fn validation_network_sandbox_available() -> bool {
    #[cfg(target_os = "macos")]
    if Path::new("/usr/bin/sandbox-exec").is_file() {
        return true;
    }
    #[cfg(target_os = "linux")]
    if kuzushi_sandbox::which("bwrap").is_some() {
        return true;
    }
    false
}

fn configure_minimal_environment(command: &mut Command, cwd: &Path) {
    command.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    command
        .env("HOME", cwd)
        .env("TMPDIR", std::env::temp_dir())
        .env("XDG_CACHE_HOME", cwd.join(".cache"))
        .env("npm_config_cache", cwd.join(".cache/npm"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_LFS_SKIP_SMUDGE", "1")
        .env("GIT_TERMINAL_PROMPT", "0");
}

fn configure_safe_git_command(command: &mut Command) {
    command.args([
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
    ]);
}

fn configure_validation_environment(command: &mut Command, cwd: &Path) -> Result<()> {
    configure_minimal_environment(command, cwd);
    let state = validation_state_root(cwd);
    for leaf in ["home", "tmp", "cache", "npm"] {
        std::fs::create_dir_all(state.join(leaf))
            .with_context(|| format!("could not create isolated validation {leaf} directory"))?;
    }
    command
        .env("HOME", state.join("home"))
        .env("TMPDIR", state.join("tmp"))
        .env("XDG_CACHE_HOME", state.join("cache"))
        .env("npm_config_cache", state.join("npm"));
    if let Some(home) = cargo_home() {
        command.env("CARGO_HOME", home);
    }
    if let Some(home) = rustup_home() {
        command.env("RUSTUP_HOME", home);
    }
    Ok(())
}

fn validation_state_root(cwd: &Path) -> PathBuf {
    cwd.join(".kuzushi-validation")
}

fn cargo_home() -> Option<PathBuf> {
    std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|home| home.join(".cargo")))
}

fn rustup_home() -> Option<PathBuf> {
    std::env::var_os("RUSTUP_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|home| home.join(".rustup")))
}

#[cfg(target_os = "macos")]
fn validation_read_paths(cwd: &Path) -> Vec<PathBuf> {
    let mut paths = vec![cwd.to_path_buf(), validation_state_root(cwd)];
    if let Some(cargo_home) = cargo_home() {
        paths.extend(["bin", "registry"].map(|leaf| cargo_home.join(leaf)));
    }
    if let Some(rustup_home) = rustup_home() {
        paths.push(rustup_home);
    }
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_process_does_not_inherit_arbitrary_environment() {
        let temp = tempfile::tempdir().unwrap();
        let mut command = Command::new("sh");
        command.arg("-c").arg("env");
        for key in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        ] {
            command.env(key, "/unsafe/source-override");
        }
        configure_minimal_environment(&mut command, temp.path());

        let output = command.output().unwrap();
        let environment = String::from_utf8_lossy(&output.stdout);

        assert!(environment.contains("HOME="));
        assert!(environment.contains("PATH="));
        assert!(!environment.contains("KUZUSHI_AGENT_MCPS="));
        assert!(!environment.contains("OPENAI_API_KEY="));
        assert!(!environment.contains("/unsafe/source-override"));
        assert!(environment.contains("GIT_NO_REPLACE_OBJECTS=1"));
    }

    #[test]
    fn disclosure_never_claims_network_denial_without_a_sandbox() {
        let disclosure = patch_network_isolation_disclosure();
        assert_eq!(
            disclosure.contains("host sandbox"),
            validation_network_sandbox_available()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn sandboxed_validation_cannot_read_operator_home_credentials() {
        let Some(home) = dirs::home_dir() else {
            return;
        };
        let protected = [".gitconfig", ".cargo/credentials.toml"]
            .into_iter()
            .map(|leaf| home.join(leaf))
            .find(|path| path.is_file());
        let Some(protected) = protected else {
            return;
        };
        let worktree = tempfile::tempdir().unwrap();
        let script = format!(
            "! /bin/cat '{}' >/dev/null 2>&1 && touch sandbox-write-ok",
            protected.display()
        );

        let output = PatchProcessControl::unattended(Duration::from_secs(5))
            .run_shell(worktree.path(), &script, "sandbox credential probe")
            .unwrap();

        assert!(
            output.status.success(),
            "sandbox probe failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(worktree.path().join("sandbox-write-ok").is_file());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn sandboxed_validation_cannot_write_outside_worktree() {
        let outer = tempfile::tempdir().unwrap();
        let worktree = outer.path().join("worktree");
        std::fs::create_dir(&worktree).unwrap();
        let outside = outer.path().join("outside-write");
        let script = format!(
            "! touch '{}' >/dev/null 2>&1 && touch inside-write",
            outside.display()
        );

        let output = PatchProcessControl::unattended(Duration::from_secs(5))
            .run_shell(&worktree, &script, "sandbox write probe")
            .unwrap();

        assert!(output.status.success());
        assert!(!outside.exists());
        assert!(worktree.join("inside-write").is_file());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn sandboxed_validation_denies_loopback_network() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let worktree = tempfile::tempdir().unwrap();
        let script = format!("/usr/bin/nc -z 127.0.0.1 {port}");

        let output = PatchProcessControl::unattended(Duration::from_secs(5))
            .run_shell(worktree.path(), &script, "sandbox network probe")
            .unwrap();

        assert!(!output.status.success());
    }
}
