use crate::command::ConfigCommand;
use anyhow::Result;
use kuzushi_core::config::write_default_config;
use kuzushi_core::WorkspaceTarget;
use std::path::{Path, PathBuf};

pub(crate) fn config_command(command: ConfigCommand, target: Option<PathBuf>) -> Result<()> {
    match command {
        ConfigCommand::Show => config_show_command(target),
        ConfigCommand::Init { force } => config_init_command(force),
        ConfigCommand::Path => config_path_command(),
    }
}

pub(crate) fn config_show_command(target: Option<PathBuf>) -> Result<()> {
    let workspace = target.as_deref().map(WorkspaceTarget::new).transpose()?;
    let config =
        super::config_diagnostics::load_cli_config(workspace.as_ref().map(WorkspaceTarget::root))?;
    println!("{}", serde_json::to_string_pretty(&config)?);
    Ok(())
}

pub(crate) fn config_init_command(force: bool) -> Result<()> {
    let path = writable_config_init_path(force)?;
    write_default_config(&path)?;
    println!("{}", path.display());
    Ok(())
}

pub(crate) fn writable_config_init_path(force: bool) -> Result<PathBuf> {
    let paths = kuzushi_core::ConfigPaths::from_target(None)?;
    let path = paths.global_config_path();
    ensure_config_init_allowed(&path, force)?;
    Ok(path)
}

pub(crate) fn ensure_config_init_allowed(path: &Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        anyhow::bail!(
            "{} already exists; pass --force to overwrite",
            path.display()
        );
    }
    Ok(())
}

pub(crate) fn config_path_command() -> Result<()> {
    let paths = kuzushi_core::ConfigPaths::from_target(None)?;
    println!("{}", paths.global_config_path().display());
    Ok(())
}
