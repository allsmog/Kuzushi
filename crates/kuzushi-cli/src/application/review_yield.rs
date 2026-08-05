use std::path::PathBuf;

use anyhow::{Context, Result};
use kuzushi_core::review_yield::application::{export_dataset, run_census};
use kuzushi_core::WorkspaceTarget;

use crate::command::ReviewYieldCommand;
use crate::presentation::review_yield_census_output;
use crate::support::require_cli_target;

pub(crate) fn review_yield_command(
    command: ReviewYieldCommand,
    global_target: Option<PathBuf>,
) -> Result<()> {
    match command {
        ReviewYieldCommand::Census { json } => {
            let target = require_cli_target("review-yield census", None, global_target)?;
            census_command(target, json)
        }
        ReviewYieldCommand::Export { output } => {
            let target = require_cli_target("review-yield export", None, global_target)?;
            export_command(target, output)
        }
    }
}

fn census_command(target: PathBuf, json: bool) -> Result<()> {
    let workspace = WorkspaceTarget::new(target)?;
    let report = run_census(&workspace)?;
    print!("{}", review_yield_census_output(&report, json)?);
    Ok(())
}

fn export_command(target: PathBuf, output: PathBuf) -> Result<()> {
    let workspace = WorkspaceTarget::new(target)?;
    let output = kuzushi_core::workspace::resolve_contained_output_path(workspace.root(), &output)
        .context("review-yield export output must resolve inside the workspace root")?;
    let outcome = export_dataset(&workspace, &output)?;
    println!(
        "review-yield: exported {} example(s) to {} (manifest {}, digest {})",
        outcome.rows,
        outcome.dataset_path.display(),
        outcome.manifest_path.display(),
        outcome.dataset_digest
    );
    Ok(())
}
