use super::*;
use crate::app::{JsonFileState, ViewDataState};

pub(crate) fn saved_worklist_run_id(app: &ShellApp) -> Option<String> {
    match app
        .workbench_cache()
        .borrow()
        .cached_saved_worklist_run(app.target())
    {
        ViewDataState::Ready(Ok(id)) => id,
        _ => None,
    }
}

pub(super) fn saved_run(app: &ShellApp) -> Result<Option<(String, u64)>, String> {
    if !reads_saved_worklist(app) {
        return Ok(None);
    }
    let id = match app
        .workbench_cache()
        .borrow()
        .cached_saved_worklist_run(app.target())
    {
        ViewDataState::Ready(result) => result?,
        _ => return Err("Loading saved ranking history; no work will run.".into()),
    };
    let Some(id) = id else {
        return Ok(None);
    };
    let target = app.target().ok_or("No ranking target selected")?;
    let version = app
        .workbench_cache()
        .borrow()
        .cached_run_artifact_version(target, &id, "result.json")
        .ok_or("Loading saved ranking result; no work will run.")?;
    Ok(Some((id, version)))
}

fn reads_saved_worklist(app: &ShellApp) -> bool {
    app.shell_view() == crate::ShellView::Scene
        && app.router.scene().page() == crate::scene3d::VizPage::Worklist
        && app
            .target()
            .is_some_and(|target| !app.domain().has_worklist_snapshot_for(target))
}

pub(super) fn project_saved(app: &ShellApp, id: &str) -> Option<WorklistViewModel> {
    let target = app.target()?;
    let read = app
        .workbench_cache()
        .borrow()
        .cached_run_artifact_json(target, id, "result.json");
    let model = match read {
        ViewDataState::Ready(JsonFileState::Present(value)) => {
            checked_projection(&value, target, id)
        }
        _ => Err(
            "Saved ranking result is missing, unreadable or malformed; inspect its run receipt."
                .into(),
        ),
    };
    Some(model.unwrap_or_else(notice))
}

fn checked_projection(
    value: &serde_json::Value,
    target: &std::path::Path,
    id: &str,
) -> Result<WorklistViewModel, String> {
    let data = &value["data"];
    if !matches!(value["status"].as_str(), Some("completed" | "partial")) {
        return Err("Saved ranking status contradicts its run receipt; inspect runs.".into());
    }
    if !saved_payload_matches_target(data, target) {
        return Err("Saved ranking target, rows or count is inconsistent; inspect runs.".into());
    }
    let mut model =
        project_snapshot(data).ok_or("Saved ranking rows are malformed; inspect runs.")?;
    model.empty_hint = None;
    model.inspection.insert(0,format!("Saved ranking from {id}; current context and source equivalence are unverified. History search covers at most 100 runs."));
    Ok(model)
}

fn saved_payload_matches_target(data: &serde_json::Value, target: &std::path::Path) -> bool {
    let Some(rows) = data["rows"].as_array() else {
        return false;
    };
    data["target"].as_str() == target.to_str()
        && data["rankedTotal"]
            .as_u64()
            .is_some_and(|total| total >= rows.len() as u64)
        && rows.len() <= 500
}

pub(super) fn notice(message: String) -> WorklistViewModel {
    WorklistViewModel {
        history_notice: Some(message),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests;
