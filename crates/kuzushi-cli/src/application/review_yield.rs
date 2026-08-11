use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use kuzushi_core::review_yield::application::{export_dataset, run_census, score_current_findings};
use kuzushi_core::review_yield::domain::ValidatedReviewYieldModel;
use kuzushi_core::review_yield::persistence::{
    eligibility_for_load_error, load_model_artifact, ReviewYieldProjectionReader,
};
use kuzushi_core::WorkspaceTarget;

use crate::command::ReviewYieldCommand;
use crate::presentation::{
    review_yield_census_output, review_yield_model_output, review_yield_score_output,
};
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
        ReviewYieldCommand::ValidateModel { model, json } => validate_model_command(&model, json),
        ReviewYieldCommand::Score { model, json } => {
            let target = require_cli_target("review-yield score", None, global_target)?;
            score_command(target, &model, json)
        }
    }
}

/// Reads a model artifact and reports what it is. Needs no target: the artifact
/// is a file, not workspace state.
pub(crate) fn validate_model_command(model: &Path, json: bool) -> Result<()> {
    let model = open_model(model)?;
    print!("{}", review_yield_model_output(&model, json)?);
    Ok(())
}

/// Scores this target's current findings. The model is opened first, so a bad
/// artifact fails before the findings store is touched.
pub(crate) fn score_command(target: PathBuf, model: &Path, json: bool) -> Result<()> {
    let model = open_model(model)?;
    let workspace = WorkspaceTarget::new(target)?;
    let reader = ReviewYieldProjectionReader::open(&workspace)?;
    let scores = score_current_findings(&reader, &model)?;
    print!("{}", review_yield_score_output(&model, &scores, json)?);
    Ok(())
}

/// A refused artifact is an error with both the reason and the eligibility the
/// runtime would report, never a warning and never a fallback model.
fn open_model(path: &Path) -> Result<ValidatedReviewYieldModel> {
    load_model_artifact(path).map_err(|error| {
        anyhow::anyhow!(
            "{error} ({}). Next: re-export the model artifact from the training run that produced it.",
            eligibility_for_load_error(&error).kind()
        )
    })
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
