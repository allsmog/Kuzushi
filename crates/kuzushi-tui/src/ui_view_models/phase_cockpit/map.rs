use super::MapPhaseModel;
use crate::ui_view_models::{
    attack_surface_model, cached_risk_by_module, context_snapshot_model, dfd_model, project_model,
};
use crate::ShellApp;

/// Build the durable Map projection.
///
/// Map deliberately does not inspect `ActivitySession`: foreground execution
/// belongs to Run Focus, while this screen describes artifacts that remain
/// true after a run finishes or another phase starts working.
pub(super) fn map_phase_model(app: &ShellApp) -> MapPhaseModel {
    let context = context_snapshot_model(app);
    let project = project_model(app);
    let attack_surface = attack_surface_model(app);
    let hot_modules = cached_risk_by_module(app);
    let dfd = dfd_model(app);
    let empty_hint = map_empty_hint(app, &context, attack_surface.is_some(), &dfd);
    MapPhaseModel {
        context,
        project,
        attack_surface,
        hot_modules,
        dfd,
        empty_hint,
    }
}

fn map_empty_hint(
    app: &ShellApp,
    context: &crate::ui_view_models::ContextSnapshotModel,
    has_attack_surface: bool,
    dfd: &crate::ui_view_models::DfdModel,
) -> Option<String> {
    let Some(target) = app.target() else {
        return Some("select a target to map its durable security artifacts".to_string());
    };
    let adequate = matches!(
        app.workbench_cache()
            .borrow()
            .cached_map_artifacts_built(Some(target)),
        crate::app::ViewDataState::Ready(true)
    );
    if adequate || !app.findings().is_empty() {
        return None;
    }
    let has_durable_artifact = context.snapshot_present
        || has_attack_surface
        || dfd.empty_hint.is_none()
        || !app.findings().is_empty();
    if has_durable_artifact {
        return Some(kuzushi_core::workflow_attempts::insufficient_map_evidence_message(target));
    }
    Some("no map artifacts yet — use `next` to start mapping".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ActivitySession, RecordedTraceEvent};
    use kuzushi_core::{RunTraceStep, V2Config};

    #[test]
    fn retained_activity_never_changes_the_durable_map_projection() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let baseline = map_phase_model(&app);
        let mut activity = ActivitySession::new("unrelated-prove-run");
        activity.events.push_back(RecordedTraceEvent {
            step: RunTraceStep {
                n: 9,
                kind: "model".to_string(),
                label: "unrelated proof output".to_string(),
                latency_ms: None,
                cost_usd: None,
                observed_cost_usd: None,
                provider_spend_unresolved: false,
                call_attempted: None,
                module_id: None,
                verb: None,
                parent_step: None,
                severity: None,
                started_at_ms: None,
                model: None,
                provider: None,
                prompt_hash: None,
            },
            observed_at: std::time::Instant::now(),
        });
        app.set_activity(Some(activity));

        assert_eq!(map_phase_model(&app), baseline);
    }
}
