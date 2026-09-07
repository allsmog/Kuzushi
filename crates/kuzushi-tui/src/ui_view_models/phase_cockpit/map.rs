use super::{MapPhaseModel, NextScanRow, NextScansState};
use crate::app::ViewDataState;
use crate::ui_view_models::{
    attack_surface_model, cached_risk_by_module, context_snapshot_model, dfd_model, project_model,
    worklist_model,
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
    let worklist = worklist_model(app);
    let next_scans = next_scans_state(app);
    let dfd = dfd_model(app);
    let threat_model_freshness = crate::ui_view_models::threat_model_freshness(app);
    let empty_hint = map_empty_hint(app, &context, attack_surface.is_some(), &dfd);
    MapPhaseModel {
        inspectable_local_artifacts: map_local_artifacts_available(app),
        context,
        project,
        attack_surface,
        hot_modules,
        worklist,
        next_scans,
        dfd,
        threat_model_freshness,
        empty_hint,
        decompose_first: decompose_first_hint(app),
    }
}

pub(crate) fn map_gallery_is_primary(app: &ShellApp) -> bool {
    map_has_gallery(&map_phase_model(app))
}

/// This presentation predicate never supplies a workflow checkpoint.
pub(super) fn map_has_gallery(model: &MapPhaseModel) -> bool {
    model.inspectable_local_artifacts || !map_requires_action(model)
}

pub(crate) fn map_local_artifacts_available(app: &ShellApp) -> bool {
    if !crate::ui_view_models::entry_point_breakdown(app)
        .entries
        .is_empty()
    {
        return true;
    }
    app.active_target_facts()
        .and_then(|facts| facts.component_inventory.as_ref())
        .is_some_and(|report| report.manifests_scanned > 0 || !report.lockfiles.is_empty())
}

/// Receipt rows the Map status card shows. The renderer takes the same number
/// of project rows, so the layout can size the card without the two surfaces
/// disagreeing about how tall it is.
pub(crate) const MAP_CONTEXT_ROW_LIMIT: usize = 8;

/// The card's heading and its artifact status line, which it always renders.
const MAP_CONTEXT_FIXED_ROWS: usize = 2;

/// Content rows the Map status card renders: heading, the optional empty
/// hint, the artifact status line, and the receipt rows. The layout bounds
/// the card to these rows instead of stretching one short card over the whole
/// body.
pub(crate) fn map_status_card_rows(model: &MapPhaseModel) -> u16 {
    let rows = MAP_CONTEXT_FIXED_ROWS
        + usize::from(model.empty_hint.is_some())
        + model.project.rows.len().min(MAP_CONTEXT_ROW_LIMIT);
    u16::try_from(rows).unwrap_or(u16::MAX)
}

pub(super) fn map_requires_action(model: &MapPhaseModel) -> bool {
    model.empty_hint.is_some()
        || model.dfd.empty_hint.is_some()
        || model.decompose_first.is_some()
        || model.threat_model_freshness.requires_attention
        || model.context.state.eq_ignore_ascii_case("stale")
        || model
            .context
            .status
            .to_ascii_lowercase()
            .contains("blocked")
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
    fn local_inventory_opens_the_gallery_without_clearing_map_prerequisites() {
        let app = ShellApp::new(V2Config::default(), None);
        let mut model = map_phase_model(&app);
        assert!(map_requires_action(&model));
        assert!(!map_has_gallery(&model));
        model.inspectable_local_artifacts = true;
        assert!(map_has_gallery(&model));
        assert!(map_requires_action(&model));
        assert!(model.dfd.empty_hint.is_some());
    }

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
