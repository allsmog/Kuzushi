use crate::command::{McpBackend, McpCommand};
use anyhow::{Context, Result};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::Duration;

pub(crate) async fn mcp_command(command: McpCommand, target: Option<PathBuf>) -> Result<()> {
    match command {
        McpCommand::Serve { backend } => serve_mcp_backend(backend, target.as_deref()),
        McpCommand::Health { backend } => health_mcp_backend(backend, target.as_deref()),
    }
}

/// A global `--target` grants the server that root, the same read capability
/// the agent bridge passes, so `kuzushi --target <repo> mcp health cpg`
/// reports that repository instead of "unresolved".
fn grant_target_read_root(command: &mut Command, target: Option<&Path>) -> Result<()> {
    if let Some(target) = target {
        command.env(
            kuzushi_mcp_common::MCP_READ_ROOTS_ENV,
            target_read_roots_json(target)?,
        );
    }
    Ok(())
}

fn target_read_roots_json(target: &Path) -> Result<String> {
    let root = std::fs::canonicalize(target)
        .with_context(|| format!("MCP target {} does not exist", target.display()))?;
    Ok(serde_json::to_string(&[root])?)
}

pub(crate) fn serve_mcp_backend(backend: McpBackend, target: Option<&Path>) -> Result<()> {
    let binary = resolve_mcp_binary(backend.binary());
    let mut command = Command::new(&binary);
    grant_target_read_root(&mut command, target)?;
    let (child, process_group) = spawn_guarded_mcp(&mut command)
        .with_context(|| mcp_spawn_error(&binary.display().to_string()))?;
    let status = wait_for_mcp_child(register_mcp_child(child, process_group)?)?;
    exit_with_mcp_status(status, &binary);
}

pub(crate) fn health_mcp_backend(backend: McpBackend, target: Option<&Path>) -> Result<()> {
    let binary = resolve_mcp_binary(backend.binary());
    let mut command = Command::new(&binary);
    grant_target_read_root(&mut command, target)?;
    command
        .arg("--health")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = guarded_mcp_output(&mut command)
        .with_context(|| mcp_health_spawn_error(&binary.display().to_string()))?;
    write_mcp_output(&output.stdout, &output.stderr);
    exit_with_mcp_status(output.status, &binary);
}

fn guarded_mcp_output(command: &mut Command) -> Result<Output> {
    let (mut child, process_group) = spawn_guarded_mcp(command)?;
    let stdout = child
        .stdout
        .take()
        .context("MCP health stdout unavailable")?;
    let stderr = child
        .stderr
        .take()
        .context("MCP health stderr unavailable")?;
    let stdout = std::thread::spawn(move || read_pipe(stdout));
    let stderr = std::thread::spawn(move || read_pipe(stderr));
    let status = wait_for_mcp_child(register_mcp_child(child, process_group)?)?;
    Ok(Output {
        status,
        stdout: join_pipe(stdout, "stdout")?,
        stderr: join_pipe(stderr, "stderr")?,
    })
}

fn spawn_guarded_mcp(
    command: &mut Command,
) -> Result<(Child, kuzushi_core::scan::PreparedProcessGroup)> {
    let process_group = kuzushi_core::scan::PreparedProcessGroup::configure(command)?;
    Ok((command.spawn()?, process_group))
}

fn register_mcp_child(
    child: Child,
    process_group: kuzushi_core::scan::PreparedProcessGroup,
) -> Result<kuzushi_core::scan::RegisteredChild> {
    kuzushi_core::scan::ScanCancellation::default().register_prepared_child(child, process_group)
}

fn wait_for_mcp_child(child: kuzushi_core::scan::RegisteredChild) -> Result<ExitStatus> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn read_pipe(mut pipe: impl Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    pipe.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn join_pipe(
    reader: std::thread::JoinHandle<std::io::Result<Vec<u8>>>,
    stream: &str,
) -> Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| anyhow::anyhow!("MCP health {stream} reader panicked"))?
        .with_context(|| format!("could not read MCP health {stream}"))
}

fn exit_with_mcp_status(status: std::process::ExitStatus, binary: &Path) -> ! {
    crate::application::config_diagnostics::exit_after_runtime_diagnostics(mcp_exit_code(
        status, binary,
    ))
}

fn mcp_exit_code(status: std::process::ExitStatus, binary: &Path) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            eprintln!("{} terminated by signal {signal}", binary.display());
            return 128_i32.saturating_add(signal);
        }
    }
    eprintln!("{} terminated without an exit status", binary.display());
    1
}

pub(crate) fn mcp_spawn_error(binary: &str) -> String {
    format!(
        "could not spawn `{binary}`. Release packages ship MCP servers next to `kuzushi`; from source, run `cargo build --workspace` or `pnpm build:native`"
    )
}

pub(crate) fn mcp_health_spawn_error(binary: &str) -> String {
    format!(
        "could not spawn `{binary} --health`. Release packages ship MCP servers next to `kuzushi`; from source, run `cargo build --workspace` or `pnpm build:native`."
    )
}

pub(crate) fn write_mcp_output(stdout: &[u8], stderr: &[u8]) {
    std::io::Write::write_all(&mut std::io::stdout(), stdout).ok();
    std::io::Write::write_all(&mut std::io::stderr(), stderr).ok();
}

fn resolve_mcp_binary(binary_name: &str) -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|executable| sibling_mcp_binary(&executable, binary_name))
        .unwrap_or_else(|| PathBuf::from(binary_name))
}

fn sibling_mcp_binary(executable: &Path, binary_name: &str) -> Option<PathBuf> {
    let file_name = if cfg!(windows) {
        format!("{binary_name}.exe")
    } else {
        binary_name.to_string()
    };
    let candidate = executable.parent()?.join(file_name);
    candidate.is_file().then_some(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_global_target_becomes_the_servers_single_read_root() {
        let temp = tempfile::tempdir().unwrap();
        let canonical = std::fs::canonicalize(temp.path()).unwrap();

        let json = target_read_roots_json(temp.path()).unwrap();

        assert_eq!(
            serde_json::from_str::<Vec<PathBuf>>(&json).unwrap(),
            vec![canonical]
        );
        assert!(target_read_roots_json(&temp.path().join("missing")).is_err());
    }

    #[test]
    fn pipe_reader_preserves_the_complete_byte_stream() {
        let bytes = read_pipe(std::io::Cursor::new(b"mcp health\nready")).unwrap();

        assert_eq!(bytes, b"mcp health\nready");
    }

    #[test]
    fn sibling_mcp_binary_prefers_packaged_runtime() {
        let temp = tempfile::tempdir().unwrap();
        let cli = temp.path().join(if cfg!(windows) {
            "kuzushi.exe"
        } else {
            "kuzushi"
        });
        let server = temp.path().join(if cfg!(windows) {
            "kuzushi-mcp-treesitter.exe"
        } else {
            "kuzushi-mcp-treesitter"
        });
        std::fs::write(&cli, b"cli").unwrap();
        std::fs::write(&server, b"server").unwrap();

        assert_eq!(
            sibling_mcp_binary(&cli, "kuzushi-mcp-treesitter"),
            Some(server)
        );
        assert!(sibling_mcp_binary(&cli, "kuzushi-mcp-missing").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn signal_killed_mcp_child_is_never_success() {
        let status = std::process::Command::new("sh")
            .args(["-c", "kill -TERM $$"])
            .status()
            .unwrap();

        assert_eq!(mcp_exit_code(status, Path::new("fixture-mcp")), 143);
    }
}
