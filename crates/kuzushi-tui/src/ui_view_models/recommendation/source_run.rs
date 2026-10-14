use super::*;

pub(super) fn loading(app: &ShellApp) -> bool {
    if app.target().is_none() {
        return false;
    }
    if !history_loaded(app) {
        return true;
    }
    let (Some(target), Some(id)) = (app.target(), run_id(app)) else {
        return false;
    };
    let cache = app.workbench_cache().borrow();
    !["result.json", "recommendations.json"].iter().all(|leaf| {
        matches!(
            cache.cached_run_artifact_json(target, &id, leaf),
            ViewDataState::Ready(_)
        )
    })
}

fn history_loaded(app: &ShellApp) -> bool {
    let cache = app.workbench_cache().borrow();
    matches!(
        cache.cached_latest_run_pointer(app.target()),
        ViewDataState::Ready(_)
    ) && matches!(
        cache.cached_run_summary_entries(app.target()),
        ViewDataState::Ready(_)
    )
}

pub(crate) fn run_id(app: &ShellApp) -> Option<String> {
    let cache = app.workbench_cache().borrow();
    let ViewDataState::Ready(LatestRunPointerState::Ready(latest)) =
        cache.cached_latest_run_pointer(app.target())
    else {
        return None;
    };
    let latest = latest.as_str().to_owned();
    let ViewDataState::Ready(crate::RunSummaryEntriesState::Ready(entries)) =
        cache.cached_run_summary_entries(app.target())
    else {
        return Some(latest);
    };
    entries
        .into_iter()
        .find_map(|entry| match entry.state {
            kuzushi_core::RunSummaryEntryState::Ready(summary) if is_report_run(&summary) => {
                Some(summary.run_id)
            }
            _ => None,
        })
        .or(Some(latest))
}

pub(super) fn history_notice(app: &ShellApp, selected: Option<&str>) -> Option<String> {
    let ViewDataState::Ready(LatestRunPointerState::Ready(latest)) = app
        .workbench_cache()
        .borrow()
        .cached_latest_run_pointer(app.target())
    else {
        return None;
    };
    let selected = selected?;
    (selected != latest.as_str()).then(|| {
        format!("Earlier report; latest activity is {}. Inspect runs for failed or unrelated work. History search is limited to 100 runs.", latest.as_str())
    })
}

fn is_report_run(summary: &kuzushi_core::RunSummary) -> bool {
    let recommender = summary.tool.as_deref() == Some("module-recommender:recommend")
        || summary.kind == "module-recommender:recommend";
    recommender && matches!(summary.status.as_str(), "completed" | "partial")
}
