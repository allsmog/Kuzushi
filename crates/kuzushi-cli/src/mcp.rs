use crate::command::{McpBackend, McpCommand};
use anyhow::{Context, Result};

pub(crate) async fn mcp_command(command: McpCommand) -> Result<()> {
    match command {
        McpCommand::Serve { backend } => serve_mcp_backend(backend),
        McpCommand::Health { backend } => health_mcp_backend(backend),
    }
}

pub(crate) fn serve_mcp_backend(backend: McpBackend) -> Result<()> {
    let binary = backend.binary();
    let status = std::process::Command::new(binary)
        .args::<[&str; 0], _>([])
        .status()
        .with_context(|| mcp_spawn_error(binary))?;
    std::process::exit(status.code().unwrap_or(0));
}

pub(crate) fn health_mcp_backend(backend: McpBackend) -> Result<()> {
    let binary = backend.binary();
    let output = std::process::Command::new(binary)
        .arg("--health")
        .output()
        .with_context(|| mcp_health_spawn_error(binary))?;
    write_mcp_output(&output.stdout, &output.stderr);
    std::process::exit(output.status.code().unwrap_or(0));
}

pub(crate) fn mcp_spawn_error(binary: &str) -> String {
    format!(
        "could not spawn `{binary}`. Build the workspace and add the target dir to PATH (e.g. `cargo build && export PATH=$PWD/target/debug:$PATH`)"
    )
}

pub(crate) fn mcp_health_spawn_error(binary: &str) -> String {
    format!(
        "could not spawn `{binary} --health`. Build the workspace and add the target dir to PATH."
    )
}

pub(crate) fn write_mcp_output(stdout: &[u8], stderr: &[u8]) {
    std::io::Write::write_all(&mut std::io::stdout(), stdout).ok();
    std::io::Write::write_all(&mut std::io::stderr(), stderr).ok();
}
