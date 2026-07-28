use super::{
    resolve_regular_executable, ReadOnlySandboxBackend, RestrictedSandboxAccess, SandboxedCommand,
};
use crate::AuthorizedDirectory;
use anyhow::Context;
use anyhow::Result;
use std::ffi::OsStr;
#[cfg(target_os = "macos")]
use std::ffi::OsString;
use std::fs::File;
use std::path::Path;
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
    let tool_root = trusted_tool_root(&program)?;
    let capability = crate::ReadRootCapability::new([tool_root.clone()])?;
    let access = RestrictedSandboxAccess {
        working_directory: input,
        tool_root: capability.authorize_directory(&tool_root)?,
        read_only: Vec::new(),
        read_write: Vec::new(),
        environment: Vec::new(),
    };
    build_resolved_command(backend, &program, args, access)
}

pub(super) fn build_restricted_command<I, S>(
    backend: ReadOnlySandboxBackend,
    program: &Path,
    args: I,
    access: RestrictedSandboxAccess,
) -> Result<SandboxedCommand>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let program = resolve_regular_executable(program.as_os_str())?;
    anyhow::ensure!(
        program.starts_with(access.tool_root.path()),
        "sandboxed executable is outside its authorized tool root"
    );
    build_resolved_command(backend, &program, args, access)
}

fn build_resolved_command<I, S>(
    backend: ReadOnlySandboxBackend,
    program: &Path,
    args: I,
    access: RestrictedSandboxAccess,
) -> Result<SandboxedCommand>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    verify_access(&access)?;
    let scratch = tempfile::Builder::new()
        .prefix("kuzushi-mcp-sandbox-")
        .tempdir()?;
    let (command, retained_handles) = match backend {
        ReadOnlySandboxBackend::MacosSeatbelt => (
            macos_command(program, args, &access, scratch.path())?,
            Vec::new(),
        ),
        ReadOnlySandboxBackend::LinuxBubblewrap => {
            linux_command(program, args, &access, scratch.path())?
        }
    };
    let mut protected = vec![access.working_directory, access.tool_root];
    protected.extend(access.read_only);
    protected.extend(access.read_write);
    Ok(SandboxedCommand {
        command,
        protected,
        scratch,
        _retained_handles: retained_handles,
    })
}

fn verify_access(access: &RestrictedSandboxAccess) -> Result<()> {
    verify_access_bounds(access)?;
    verify_environment(access)?;
    access.working_directory.verify_unchanged()?;
    access.tool_root.verify_unchanged()?;
    access
        .read_only
        .iter()
        .try_for_each(AuthorizedDirectory::verify_unchanged)?;
    access
        .read_write
        .iter()
        .try_for_each(AuthorizedDirectory::verify_unchanged)
}

fn verify_access_bounds(access: &RestrictedSandboxAccess) -> Result<()> {
    anyhow::ensure!(
        access.read_only.len() <= 4,
        "sandbox supports at most four extra read-only roots"
    );
    anyhow::ensure!(
        access.read_write.len() <= 4,
        "sandbox supports at most four writable roots"
    );
    anyhow::ensure!(
        access.environment.len() <= 8,
        "sandbox supports at most eight explicit environment variables"
    );
    Ok(())
}

fn verify_environment(access: &RestrictedSandboxAccess) -> Result<()> {
    for (name, _) in &access.environment {
        anyhow::ensure!(
            name == "CODEQL_DIST",
            "sandbox environment variable is not adapter-approved: {}",
            name.to_string_lossy()
        );
    }
    anyhow::ensure!(
        access
            .environment
            .iter()
            .filter(|(name, _)| name == "CODEQL_DIST")
            .count()
            <= 1,
        "sandbox environment contains duplicate CODEQL_DIST values"
    );
    if let Some((_, value)) = access
        .environment
        .iter()
        .find(|(name, _)| name == "CODEQL_DIST")
    {
        anyhow::ensure!(
            Path::new(value) == access.tool_root.path(),
            "CODEQL_DIST must identify the authorized tool root"
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_command<I, S>(
    program: &Path,
    args: I,
    access: &RestrictedSandboxAccess,
    scratch: &Path,
) -> Result<Command>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let scratch =
        std::fs::canonicalize(scratch).context("could not canonicalize sandbox scratch")?;
    let mut command = Command::new("/usr/bin/sandbox-exec");
    command
        .arg("-D")
        .arg(parameter("TARGET_ROOT", access.working_directory.path()))
        .arg("-D")
        .arg(parameter("TOOL_ROOT", access.tool_root.path()))
        .arg("-D")
        .arg(parameter("SCRATCH_ROOT", &scratch));
    append_macos_roots(&mut command, "READ_ROOT", &access.read_only, &scratch);
    append_macos_roots(&mut command, "WRITE_ROOT", &access.read_write, &scratch);
    command
        .arg("-p")
        .arg(MACOS_PROFILE)
        .arg(program)
        .args(args)
        .current_dir(access.working_directory.path())
        .env_clear()
        .env("PATH", FIXED_PATH)
        .env("HOME", &scratch)
        .env("TMPDIR", &scratch)
        .env("LANG", "C.UTF-8")
        .envs(access.environment.iter().cloned())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    Ok(command)
}

#[cfg(target_os = "macos")]
fn append_macos_roots(
    command: &mut Command,
    prefix: &str,
    roots: &[AuthorizedDirectory],
    fallback: &Path,
) {
    for index in 0..4 {
        let name = format!("{prefix}_{index}");
        let path = roots.get(index).map_or(fallback, AuthorizedDirectory::path);
        command.arg("-D").arg(parameter(&name, path));
    }
}

#[cfg(not(target_os = "macos"))]
fn macos_command<I, S>(
    _program: &Path,
    _args: I,
    _access: &RestrictedSandboxAccess,
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
    access: &RestrictedSandboxAccess,
    scratch: &Path,
) -> Result<(Command, Vec<File>)>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let bwrap = trusted_bwrap().context("trusted bubblewrap is unavailable")?;
    let mut command = Command::new(bwrap);
    append_linux_isolation(&mut command);
    append_linux_system_roots(&mut command);
    let (retained_handles, scratch) = append_linux_access(&mut command, access, scratch)?;
    append_linux_environment(&mut command, access, &scratch);
    command
        .arg("--chdir")
        .arg(access.working_directory.path())
        .arg("--")
        .arg(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    Ok((command, retained_handles))
}

#[cfg(target_os = "linux")]
fn append_linux_access(
    command: &mut Command,
    access: &RestrictedSandboxAccess,
    scratch: &Path,
) -> Result<(Vec<File>, PathBuf)> {
    let mut retained_handles = Vec::new();
    append_linux_authorized_root(command, &access.tool_root, true, &mut retained_handles)?;
    append_linux_authorized_root(
        command,
        &access.working_directory,
        true,
        &mut retained_handles,
    )?;
    for root in &access.read_only {
        append_linux_authorized_root(command, root, true, &mut retained_handles)?;
    }
    for root in &access.read_write {
        append_linux_authorized_root(command, root, false, &mut retained_handles)?;
    }
    let scratch_capability = crate::ReadRootCapability::new([scratch.to_path_buf()])?;
    let scratch = scratch_capability.authorize_directory(scratch)?;
    append_linux_authorized_root(command, &scratch, false, &mut retained_handles)?;
    Ok((retained_handles, scratch.path().to_path_buf()))
}

#[cfg(target_os = "linux")]
fn append_linux_environment(
    command: &mut Command,
    access: &RestrictedSandboxAccess,
    scratch: &Path,
) {
    command
        .arg("--setenv")
        .arg("HOME")
        .arg(scratch)
        .arg("--setenv")
        .arg("TMPDIR")
        .arg(scratch);
    for (name, value) in &access.environment {
        command.arg("--setenv").arg(name).arg(value);
    }
}

#[cfg(target_os = "linux")]
fn append_linux_authorized_root(
    command: &mut Command,
    root: &AuthorizedDirectory,
    read_only: bool,
    retained_handles: &mut Vec<File>,
) -> Result<()> {
    use std::os::fd::AsRawFd;

    if read_only && fixed_linux_root_contains(root.path()) {
        return Ok(());
    }
    let retained = root.retained_handle()?;
    clear_close_on_exec(retained.as_raw_fd())?;
    let retained_path = PathBuf::from(format!("/proc/self/fd/{}", retained.as_raw_fd()));
    append_parent_directories(command, root.path());
    command
        .arg(if read_only { "--ro-bind" } else { "--bind" })
        .arg(retained_path)
        .arg(root.path());
    retained_handles.push(retained);
    Ok(())
}

#[cfg(target_os = "linux")]
fn fixed_linux_root_contains(path: &Path) -> bool {
    ["/usr", "/usr/local", "/lib", "/lib64", "/bin", "/sbin"]
        .iter()
        .any(|candidate| path.starts_with(candidate))
}

#[cfg(not(target_os = "linux"))]
fn linux_command<I, S>(
    _program: &Path,
    _args: I,
    _access: &RestrictedSandboxAccess,
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
    (path-ancestors (param "SCRATCH_ROOT"))
    (path-ancestors (param "READ_ROOT_0"))
    (path-ancestors (param "READ_ROOT_1"))
    (path-ancestors (param "READ_ROOT_2"))
    (path-ancestors (param "READ_ROOT_3"))
    (path-ancestors (param "WRITE_ROOT_0"))
    (path-ancestors (param "WRITE_ROOT_1"))
    (path-ancestors (param "WRITE_ROOT_2"))
    (path-ancestors (param "WRITE_ROOT_3")))
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
    (subpath (param "READ_ROOT_0"))
    (subpath (param "READ_ROOT_1"))
    (subpath (param "READ_ROOT_2"))
    (subpath (param "READ_ROOT_3"))
    (subpath (param "WRITE_ROOT_0"))
    (subpath (param "WRITE_ROOT_1"))
    (subpath (param "WRITE_ROOT_2"))
    (subpath (param "WRITE_ROOT_3"))
    (literal "/dev/null")
    (literal "/dev/urandom"))
(allow file-write*
    (subpath (param "SCRATCH_ROOT"))
    (subpath (param "WRITE_ROOT_0"))
    (subpath (param "WRITE_ROOT_1"))
    (subpath (param "WRITE_ROOT_2"))
    (subpath (param "WRITE_ROOT_3"))
    (literal "/dev/null"))
(deny network*)
"#;
