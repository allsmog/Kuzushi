use super::{MapPhaseModel, NextScanRow, NextScansState};
use crate::app::ViewDataState;
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
    let next_scans = next_scans_state(app);
    let dfd = dfd_model(app);
    let empty_hint = map_empty_hint(app, &context, attack_surface.is_some(), &dfd);
    MapPhaseModel {
        context,
        project,
        attack_surface,
        hot_modules,
        next_scans,
        dfd,
        empty_hint,
        decompose_first: decompose_first_hint(app),
    }
}

/// Recommend module decomposition before threat modeling when the indexed
/// repository is monorepo-sized and no nested scope decomposition exists yet.
/// A persisted scope tree (or an unhydrated/unreadable verdict) keeps the
/// regular threat-model recommendation.
fn decompose_first_hint(app: &ShellApp) -> Option<String> {
    let files = app.domain().context_view().files_indexed?;
    if files < crate::app::DECOMPOSE_FIRST_FILE_THRESHOLD {
        return None;
    }
    let tree = app
        .workbench_cache()
        .borrow()
        .cached_project_scope_tree(app.target());
    let undecomposed = matches!(
        tree,
        ViewDataState::Ready(crate::app::ProjectScopeTreeState::RootOnly)
    );
    undecomposed
        .then(|| format!("{files} files indexed — break the target into logical modules first"))
}

const NEXT_SCAN_ROW_LIMIT: usize = 4;

pub(super) fn next_scans_state(app: &ShellApp) -> NextScansState {
    let cached = app
        .workbench_cache()
        .borrow()
        .cached_scan_recommendations(app.target());
    let ViewDataState::Ready(state) = cached else {
        return NextScansState::Pending;
    };
    match state {
        crate::app::ScanRecommendationsState::Ready(rows) => NextScansState::Ready(
            rows.iter()
                .take(NEXT_SCAN_ROW_LIMIT)
                .map(next_scan_row)
                .collect(),
        ),
        crate::app::ScanRecommendationsState::Failed(error) => NextScansState::Unavailable(error),
    }
}

fn next_scan_row(
    recommendation: &kuzushi_core::capabilities::scan_recommender::ScanRecommendation,
) -> NextScanRow {
    NextScanRow {
        scope: recommendation.scope_id.clone(),
        phase: recommendation.phase.word().to_string(),
        reason: recommendation.reason.label().to_string(),
        evidence: recommendation.evidence.clone(),
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
    let built = app
        .workbench_cache()
        .borrow()
        .cached_map_artifacts_built(Some(target));
    if matches!(built, ViewDataState::Ready(true)) || !app.findings().is_empty() {
        return None;
    }
    // While the evidence verdict is still hydrating, don't assert "no
    // analyzable evidence" beside a context pane that may show some.
    if !matches!(built, ViewDataState::Ready(false)) {
        return Some("checking durable map artifacts…".to_string());
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
    use crate::ActivitySession;
    use kuzushi_core::V2Config;

    #[test]
    fn retained_activity_never_changes_the_durable_map_projection() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let baseline = map_phase_model(&app);
        let activity = ActivitySession::new("unrelated-prove-run");
        app.set_activity(Some(activity));

        assert_eq!(map_phase_model(&app), baseline);
    }

    #[test]
    fn map_hint_stays_silent_until_the_evidence_verdict_hydrates() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));

        // Verdict not requested yet: a neutral placeholder, no claim either way.
        assert_eq!(
            map_phase_model(&app).empty_hint.as_deref(),
            Some("checking durable map artifacts…")
        );

        app.hydrate_all_view_data_for_test();
        let hint = map_phase_model(&app).empty_hint.expect("hydrated hint");
        assert!(
            hint.contains("no map artifacts yet"),
            "empty target guidance after hydration: {hint}"
        );
    }

    #[test]
    fn monorepo_without_scope_tree_recommends_decomposition_first() {
        let target = std::path::PathBuf::from("/tmp/decompose-first-target");
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(target.clone()));
        app.domain_mut().context_view_mut().files_indexed = Some(81_259);

        // Scope-tree verdict not hydrated yet: no premature recommendation.
        assert_eq!(map_phase_model(&app).decompose_first, None);

        let hydrate = |state: crate::app::ProjectScopeTreeState| crate::app::ViewHydrationResult {
            target: target.clone(),
            key: crate::app::ViewHydrationKey::ProjectScopeTree,
            value: crate::app::ViewHydrationValue::ProjectScopeTree(state),
        };
        app.workbench_cache()
            .borrow_mut()
            .apply_view_hydration(hydrate(crate::app::ProjectScopeTreeState::RootOnly));
        let hint = map_phase_model(&app)
            .decompose_first
            .expect("monorepo without decomposition must recommend it first");
        assert!(hint.contains("81259 files indexed"), "{hint}");

        // An existing decomposition or a small repository keeps the normal
        // threat-model recommendation.
        let tree = kuzushi_core::discover_nested_project_scopes(std::path::Path::new("/tmp"));
        app.workbench_cache()
            .borrow_mut()
            .apply_view_hydration(hydrate(crate::app::ProjectScopeTreeState::Persisted(tree)));
        assert_eq!(map_phase_model(&app).decompose_first, None);

        app.workbench_cache()
            .borrow_mut()
            .apply_view_hydration(hydrate(crate::app::ProjectScopeTreeState::RootOnly));
        app.domain_mut().context_view_mut().files_indexed = Some(1_200);
        assert_eq!(map_phase_model(&app).decompose_first, None);
    }

    #[test]
    fn hydrated_recommendations_project_into_next_scan_rows() {
        let target = std::path::PathBuf::from("/tmp/next-scans-target");
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(target.clone()));
        assert_eq!(map_phase_model(&app).next_scans, NextScansState::Pending);

        let recommendation = kuzushi_core::capabilities::scan_recommender::ScanRecommendation {
            scope_id: "root".to_string(),
            phase: kuzushi_core::WorkflowPhase::Scan,
            reason: kuzushi_core::capabilities::scan_recommender::ReasonTag::Changed,
            score: 0.7,
            evidence: "14 files changed since a1b2c3d4".to_string(),
            suggested_mode: None,
        };
        app.workbench_cache()
            .borrow_mut()
            .apply_view_hydration(crate::app::ViewHydrationResult {
                target,
                key: crate::app::ViewHydrationKey::ScanRecommendations,
                value: crate::app::ViewHydrationValue::ScanRecommendations(
                    crate::app::ScanRecommendationsState::Ready(vec![recommendation]),
                ),
            });

        assert_eq!(
            map_phase_model(&app).next_scans,
            NextScansState::Ready(vec![NextScanRow {
                scope: "root".to_string(),
                phase: "scan".to_string(),
                reason: "changed".to_string(),
                evidence: "14 files changed since a1b2c3d4".to_string(),
            }])
        );
    }
}
