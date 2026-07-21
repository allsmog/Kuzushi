use crate::command::{McpBackend, McpCommand};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub(crate) async fn mcp_command(command: McpCommand) -> Result<()> {
    match command {
        McpCommand::Serve { backend } => serve_mcp_backend(backend),
        McpCommand::Health { backend } => health_mcp_backend(backend),
    }
}

pub(crate) fn serve_mcp_backend(backend: McpBackend) -> Result<()> {
    let binary = resolve_mcp_binary(backend.binary());
    let status = std::process::Command::new(&binary)
        .args::<[&str; 0], _>([])
        .status()
        .with_context(|| mcp_spawn_error(&binary.display().to_string()))?;
    exit_with_mcp_status(status, &binary);
}

pub(crate) fn health_mcp_backend(backend: McpBackend) -> Result<()> {
    let binary = resolve_mcp_binary(backend.binary());
    let output = std::process::Command::new(&binary)
        .arg("--health")
        .output()
        .with_context(|| mcp_health_spawn_error(&binary.display().to_string()))?;
    write_mcp_output(&output.stdout, &output.stderr);
    exit_with_mcp_status(output.status, &binary);
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
