use super::prelude::*;
use super::*;

pub(crate) fn plain_output_requested(flag: bool) -> bool {
    flag || std::env::var_os("KUZUSHI_PLAIN").is_some()
        || std::env::var_os("KUZUSHI_SCREEN_READER").is_some()
        || std::env::var_os("KUZUSHI_LOW_BANDWIDTH").is_some()
}

pub(crate) fn should_emit_shell_startup_progress(plain: bool) -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal() && io::stderr().is_terminal() && !plain
}

pub(crate) fn shell_startup_progress_messages(target: Option<&Path>) -> Vec<String> {
    let target_label = target
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "none".to_string());
    let scan_command = if target.is_some() { "scan" } else { "scan ." };
    vec![
        "kuzushi: loading config and native registry...".to_string(),
        format!("kuzushi: target {target_label}; first finding: {scan_command}, then findings"),
    ]
}

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

pub(crate) fn pr_comment_command(
    target: Option<PathBuf>,
    repo: Option<String>,
    run_url: Option<String>,
    top_n: usize,
    changed_files: Vec<String>,
    run_id: Option<String>,
    model: Option<String>,
    git_sha: Option<String>,
) -> Result<()> {
    let target = target.unwrap_or_else(|| PathBuf::from("."));
    let workspace = WorkspaceTarget::new(target)?;
    let input = load_pr_comment_input(
        &workspace,
        repo,
        run_url,
        top_n,
        changed_files,
        run_id,
        model,
        git_sha,
    )?;
    println!("{}", build_pr_comment(&input));
    Ok(())
}
