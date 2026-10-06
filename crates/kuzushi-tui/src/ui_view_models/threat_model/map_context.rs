use super::*;
use crate::app::ShellView;
use kuzushi_core::workflow_attempts::{MapRunContext, PhaseAttemptRecord};
use kuzushi_core::WorkflowPhase;

pub(crate) fn map_context_run_refs(app: &ShellApp) -> Option<Vec<String>> {
    map_context_attempt(app).map(|record| record.completed.run_refs.clone())
}

fn map_context_attempt(app: &ShellApp) -> Option<&PhaseAttemptRecord> {
    app.engagement
        .unresolved_phase_attempt(WorkflowPhase::Map)
        .or_else(|| app.engagement.selected_phase_attempt(WorkflowPhase::Map))
        .or_else(|| {
            app.engagement
                .stale_selected_phase_attempt(WorkflowPhase::Map)
        })
}

fn context_read(app: &ShellApp) -> Option<ViewDataState<Result<Option<MapRunContext>, String>>> {
    if matches!(
        app.shell_view(),
        ShellView::Threat | ShellView::ThreatEditor | ShellView::ProjectModel
    ) {
        return None;
    }
    let runs = map_context_run_refs(app)?;
    Some(
        app.workbench_cache()
            .borrow()
            .cached_map_run_context(app.target()?, &runs),
    )
}

pub(super) fn recorded_map_artifact(app: &ShellApp) -> Option<ThreatModelArtifact> {
    Some(match context_read(app)? {
        ViewDataState::Ready(Ok(Some(context))) => ThreatModelArtifact::Present(context.document),
        ViewDataState::Ready(Ok(None)) => ThreatModelArtifact::Unavailable(
            "This Map attempt produced no threat-model context. Its other evidence remains available.".into()),
        ViewDataState::Ready(Err(error)) => ThreatModelArtifact::Unavailable(
            format!("Recorded Map context unavailable: {error}")),
        ViewDataState::NotRequested | ViewDataState::Loading => ThreatModelArtifact::Unavailable(
            "Checking recorded Map context…".into()),
    })
}

pub(super) fn recorded_map_summary_status(app: &ShellApp) -> Option<&'static str> {
    context_read(app)?;
    Some(match selection_label(app) {
        "accepted" => "accepted Map context",
        "awaiting review" => "Map context awaiting review",
        _ => "historical Map context",
    })
}

pub(crate) fn recorded_map_context_issue(app: &ShellApp) -> Option<String> {
    match recorded_map_artifact(app)? {
        ThreatModelArtifact::Unavailable(reason) => Some(reason),
        _ => None,
    }
}

pub(super) fn recorded_map_freshness(app: &ShellApp) -> Option<ThreatModelFreshnessModel> {
    let state = context_read(app)?;
    let (verdict, digest, unavailable) = match state {
        ViewDataState::Ready(Ok(Some(context))) => (
            context_label(&context),
            context.model_ref.map(|r| r.sha256),
            false,
        ),
        ViewDataState::Ready(Ok(None)) => ("Map context absent".into(), None, false),
        ViewDataState::Ready(Err(_)) => ("Map context unavailable".into(), None, true),
        ViewDataState::NotRequested | ViewDataState::Loading => {
            ("checking Map context".into(), None, false)
        }
    };
    Some(ThreatModelFreshnessModel {
        verdict: format!("{} · {verdict}", selection_label(app)),
        document_sha256: digest.clone(),
        current_sha256: digest,
        requires_attention: unavailable,
    })
}

fn context_label(context: &MapRunContext) -> String {
    let reference = context.model_ref.as_ref().map_or_else(
        || "recorded Map document".into(),
        |reference| {
            format!(
                "Map {}",
                reference
                    .revision_id
                    .as_str()
                    .chars()
                    .take(12)
                    .collect::<String>()
            )
        },
    );
    let grounding = context
        .document
        .pointer("/verification/verdict")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unrecorded");
    format!("grounding {grounding} · {reference}")
}

fn selection_label(app: &ShellApp) -> &'static str {
    if app
        .engagement
        .unresolved_phase_attempt(WorkflowPhase::Map)
        .is_some()
    {
        return "awaiting review";
    }
    if app
        .engagement
        .selected_phase_attempt(WorkflowPhase::Map)
        .is_some()
    {
        return "accepted";
    }
    "historical source"
}

#[cfg(test)]
mod tests;
