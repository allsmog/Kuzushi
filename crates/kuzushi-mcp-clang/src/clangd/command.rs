use anyhow::{Context, Result};
use kuzushi_mcp_common::compile_database::CompileDatabaseSnapshot;
use std::process::Stdio;

pub(crate) async fn clangd_command(
    repo: kuzushi_mcp_common::AuthorizedDirectory,
    database: Option<&CompileDatabaseSnapshot>,
) -> Result<kuzushi_mcp_common::read_only_sandbox::SandboxedCommand> {
    use kuzushi_mcp_common::read_only_sandbox::{read_only_command, resolve_regular_executable};

    let clangd = resolve_regular_executable(std::ffi::OsStr::new("clangd"))?;
    let mut sandboxed = if let Some(database) = database {
        selected_database_command(&clangd, repo, database).await?
    } else {
        read_only_command(&clangd, ["--background-index=false", "--log=error"], repo).await?
    };
    sandboxed
        .command_mut()?
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    Ok(sandboxed)
}

async fn selected_database_command(
    program: &std::path::Path,
    repo: kuzushi_mcp_common::AuthorizedDirectory,
    database: &CompileDatabaseSnapshot,
) -> Result<kuzushi_mcp_common::read_only_sandbox::SandboxedCommand> {
    use kuzushi_mcp_common::read_only_sandbox::{restricted_command, RestrictedSandboxAccess};
    use kuzushi_mcp_common::ReadRootCapability;

    database.verify_unchanged()?;
    let tool_root = program
        .parent()
        .context("clangd has no executable directory")?;
    let capability =
        ReadRootCapability::new([tool_root.to_path_buf(), database.directory().to_path_buf()])?;
    let access = RestrictedSandboxAccess {
        working_directory: repo,
        tool_root: capability.authorize_directory(tool_root)?,
        read_only: vec![capability.authorize_directory(database.directory())?],
        read_write: Vec::new(),
        environment: Vec::new(),
    };
    restricted_command(program, selected_database_arguments(database), access).await
}

fn selected_database_arguments(database: &CompileDatabaseSnapshot) -> Vec<std::ffi::OsString> {
    let mut selected = std::ffi::OsString::from("--compile-commands-dir=");
    selected.push(database.directory());
    [
        "--background-index=false",
        "--log=error",
        "--enable-config=false",
        "--query-driver=",
    ]
    .map(std::ffi::OsString::from)
    .into_iter()
    .chain([selected])
    .collect()
}
