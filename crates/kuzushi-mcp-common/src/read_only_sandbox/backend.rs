use super::{resolve_regular_executable, ReadOnlySandboxBackend, SandboxedCommand};
use crate::AuthorizedDirectory;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use anyhow::Context;
use anyhow::Result;
use std::ffi::OsStr;
#[cfg(target_os = "macos")]
use std::ffi::OsString;
use std::fs::File;
use std::path::Path;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::PathBuf;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Stdio;
use tokio::process::Command;

#[cfg(any(target_os = "linux", target_os = "macos"))]
const FIXED_PATH: &str = "/usr/bin:/bin:/usr/local/bin";

pub(super) fn build_command<I, S>(
    backend: ReadOnlySandboxBackend,
    program: &Path,
    args: I,
    input: AuthorizedDirectory,
) -> Result<SandboxedCommand>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let program = resolve_regular_executable(program.as_os_str())?;
    input.verify_unchanged()?;
    let scratch = tempfile::Builder::new()
        .prefix("kuzushi-mcp-sandbox-")
        .tempdir()?;
    let (command, retained_handles) = match backend {
        ReadOnlySandboxBackend::MacosSeatbelt => (
            macos_command(&program, args, &input, scratch.path())?,
            Vec::new(),
        ),
        ReadOnlySandboxBackend::LinuxBubblewrap => {
            linux_command(&program, args, &input, scratch.path())?
        }
    };
    Ok(SandboxedCommand {
        command,
        input,
        scratch,
        _retained_handles: retained_handles,
    })
}

#[cfg(target_os = "macos")]
fn macos_command<I, S>(
    program: &Path,
    args: I,
    input: &AuthorizedDirectory,
    scratch: &Path,
) -> Result<Command>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let tool_root = trusted_tool_root(program)?;
    let scratch =
        std::fs::canonicalize(scratch).context("could not canonicalize sandbox scratch")?;
    let mut command = Command::new("/usr/bin/sandbox-exec");
    command
        .arg("-D")
        .arg(parameter("TARGET_ROOT", input.path()))
        .arg("-D")
        .arg(parameter("TOOL_ROOT", &tool_root))
        .arg("-D")
        .arg(parameter("SCRATCH_ROOT", &scratch))
        .arg("-p")
        .arg(MACOS_PROFILE)
        .arg(program)
        .args(args)
        .current_dir(input.path())
        .env_clear()
        .env("PATH", FIXED_PATH)
        .env("HOME", &scratch)
        .env("TMPDIR", &scratch)
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    Ok(command)
}

#[cfg(not(target_os = "macos"))]
fn macos_command<I, S>(
    _program: &Path,
    _args: I,
    _input: &AuthorizedDirectory,
    _scratch: &Path,
) -> Result<Command>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    anyhow::bail!("macOS Seatbelt is unavailable on this platform")
}

#[cfg(target_os = "linux")]
fn linux_command<I, S>(
    program: &Path,
    args: I,
    input: &AuthorizedDirectory,
    _scratch: &Path,
) -> Result<(Command, Vec<File>)>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    use std::os::fd::AsRawFd;

    let bwrap = trusted_bwrap().context("trusted bubblewrap is unavailable")?;
    let retained = input.retained_handle()?;
    clear_close_on_exec(retained.as_raw_fd())?;
    let retained_path = PathBuf::from(format!("/proc/self/fd/{}", retained.as_raw_fd()));
    let mut command = Command::new(bwrap);
    append_linux_isolation(&mut command);
    append_linux_system_roots(&mut command);
    append_parent_directories(&mut command, input.path());
    append_linux_tool_root(&mut command, program)?;
    command
        .arg("--ro-bind")
        .arg(retained_path)
        .arg(input.path())
        .arg("--chdir")
        .arg(input.path())
        .arg("--")
        .arg(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    Ok((command, vec![retained]))
}

#[cfg(not(target_os = "linux"))]
fn linux_command<I, S>(
    _program: &Path,
    _args: I,
    _input: &AuthorizedDirectory,
    _scratch: &Path,
) -> Result<(Command, Vec<File>)>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    anyhow::bail!("Linux bubblewrap is unavailable on this platform")
}

#[cfg(target_os = "linux")]
fn append_linux_isolation(command: &mut Command) {
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
        "--clearenv",
        "--setenv",
        "PATH",
        FIXED_PATH,
        "--setenv",
        "HOME",
        "/tmp",
        "--setenv",
        "TMPDIR",
        "/tmp",
        "--setenv",
        "LANG",
        "C.UTF-8",
    ]);
}

#[cfg(target_os = "linux")]
fn append_linux_system_roots(command: &mut Command) {
    append_existing_roots(
        command,
        &["/usr", "/usr/local", "/lib", "/lib64", "/bin", "/sbin"],
    );
    for path in ["/etc/alternatives", "/etc/ssl"] {
        let path = Path::new(path);
        if path.exists() {
            append_parent_directories(command, path);
            command.arg("--ro-bind").arg(path).arg(path);
        }
    }
}

#[cfg(target_os = "linux")]
fn append_existing_roots(command: &mut Command, roots: &[&str]) {
    for path in roots.iter().map(Path::new).filter(|path| path.exists()) {
        command.arg("--ro-bind").arg(path).arg(path);
    }
}

#[cfg(target_os = "linux")]
fn append_linux_tool_root(command: &mut Command, program: &Path) -> Result<()> {
    let root = trusted_tool_root(program)?;
    if !fixed_linux_root_contains(&root) {
        append_parent_directories(command, &root);
        command.arg("--ro-bind").arg(&root).arg(&root);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn fixed_linux_root_contains(path: &Path) -> bool {
    ["/usr", "/usr/local", "/lib", "/lib64", "/bin", "/sbin"]
        .iter()
        .any(|root| path.starts_with(root))
}

#[cfg(target_os = "linux")]
fn append_parent_directories(command: &mut Command, path: &Path) {
    let mut parent = PathBuf::from("/");
    for component in path.components().skip(1) {
        parent.push(component);
        if parent != path {
            command.arg("--dir").arg(&parent);
        }
    }
}

#[cfg(target_os = "linux")]
fn clear_close_on_exec(fd: std::os::fd::RawFd) -> Result<()> {
    // SAFETY: `fd` is an owned live duplicate retained by `SandboxedCommand`.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    anyhow::ensure!(flags >= 0, "could not inspect retained sandbox descriptor");
    // SAFETY: clearing FD_CLOEXEC preserves only this descriptor in the sandbox launcher.
    let result = unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
    anyhow::ensure!(result == 0, "could not retain sandbox input descriptor");
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn trusted_tool_root(program: &Path) -> Result<PathBuf> {
    program
        .parent()
        .map(Path::to_path_buf)
        .context("sandboxed executable has no parent directory")
}

#[cfg(target_os = "macos")]
pub(super) fn parameter(name: &str, value: &Path) -> OsString {
    let mut parameter = OsString::from(name);
    parameter.push("=");
    parameter.push(value);
    parameter
}

pub(super) fn detect_backend() -> Option<ReadOnlySandboxBackend> {
    #[cfg(target_os = "macos")]
    if Path::new("/usr/bin/sandbox-exec").is_file() {
        return Some(ReadOnlySandboxBackend::MacosSeatbelt);
    }
    #[cfg(target_os = "linux")]
    if trusted_bwrap().is_some() {
        return Some(ReadOnlySandboxBackend::LinuxBubblewrap);
    }
    None
}

#[cfg(target_os = "linux")]
pub(super) fn trusted_bwrap() -> Option<PathBuf> {
    ["/usr/bin/bwrap", "/bin/bwrap"]
        .iter()
        .map(PathBuf::from)
        .find(|path| trusted_fixed_launcher(path))
}

#[cfg(target_os = "linux")]
fn trusted_fixed_launcher(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    let Ok(canonical) = std::fs::canonicalize(path) else {
        return false;
    };
    let Ok(metadata) = canonical.metadata() else {
        return false;
    };
    metadata.is_file()
        && metadata.permissions().mode() & 0o111 != 0
        && metadata.permissions().mode() & 0o022 == 0
}

#[cfg(target_os = "macos")]
pub(super) const MACOS_PROFILE: &str = r#"
(version 1)
(import "system.sb")
(deny default)
(allow process*)
(allow signal (target self))
(allow file-read-metadata file-test-existence
    (path-ancestors (param "TOOL_ROOT"))
    (path-ancestors (param "TARGET_ROOT"))
    (path-ancestors (param "SCRATCH_ROOT")))
(allow file-read*
    (subpath "/System")
    (subpath "/usr")
    (subpath "/bin")
    (subpath "/sbin")
    (subpath "/Library/Apple")
    (subpath "/Library/Developer/CommandLineTools")
    (subpath "/Applications/Xcode.app/Contents/Developer/Toolchains")
    (subpath (param "TOOL_ROOT"))
    (subpath (param "TARGET_ROOT"))
    (subpath (param "SCRATCH_ROOT"))
    (literal "/dev/null")
    (literal "/dev/urandom"))
(allow file-write*
    (subpath (param "SCRATCH_ROOT"))
    (literal "/dev/null"))
(deny network*)
"#;
