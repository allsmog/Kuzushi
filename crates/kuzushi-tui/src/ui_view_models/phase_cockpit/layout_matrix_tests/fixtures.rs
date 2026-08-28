use super::fixture_support::{
    fixture_dfd, fixture_finding, fixture_findings, fixture_proof, fixture_remediation,
    fixture_report, fixture_review_queue,
};
use super::*;
use crate::ui_view_models::{
    AttackSurfaceRiskModel, ContextSnapshotModel, ModuleRisk, ProjectModel, RiskByModule,
    TaintFlowPath, TaintStageModel,
};

pub(super) fn fixture_body(phase: WorkflowPhase, state: SemanticFixture) -> PhaseCockpitBody {
    match phase {
        WorkflowPhase::Map => PhaseCockpitBody::Map(map_fixture(state)),
        WorkflowPhase::Scan => PhaseCockpitBody::Scan(scan_fixture(state)),
        WorkflowPhase::Review => PhaseCockpitBody::Review(review_fixture(state)),
        WorkflowPhase::Prove => PhaseCockpitBody::Prove(prove_fixture(state)),
        WorkflowPhase::Fix => PhaseCockpitBody::Fix(fix_fixture(state)),
    }
}

fn map_fixture(state: SemanticFixture) -> MapPhaseModel {
    let richness = state.richness();
    MapPhaseModel {
        context: fixture_context(state, richness),
        project: ProjectModel {
            scope_label: "fixture".to_string(),
            revision_label: "rev:test".to_string(),
            rows: Vec::new(),
            next_hint: "fixture",
        },
        attack_surface: (richness >= 1).then(|| AttackSurfaceRiskModel {
            summary: "one real surface".to_string(),
            hot_surfaces: Vec::new(),
        }),
        hot_modules: fixture_hot_modules(richness),
        worklist: crate::ui_view_models::WorklistViewModel::default(),
        next_scans: super::super::NextScansState::Pending,
        dfd: fixture_dfd(richness >= 3),
        empty_hint: (richness == 0).then_some("fixture empty".to_string()),
        decompose_first: None,
    }
}

fn fixture_context(state: SemanticFixture, richness: usize) -> ContextSnapshotModel {
    ContextSnapshotModel {
        snapshot: ".kuzushi/context.json".to_string(),
        snapshot_present: richness > 0,
        state: if state == SemanticFixture::Stale {
            "stale"
        } else {
            "present"
        },
        status: format!("fixture {state:?}"),
        running: None,
        details: None,
    }
}

fn fixture_hot_modules(richness: usize) -> RiskByModule {
    RiskByModule {
        modules: (richness >= 2)
            .then(|| ModuleRisk {
                module: "src/認証".to_string(),
                counts: [0, 1, 0, 0, 0],
                score: 5.0,
            })
            .into_iter()
            .collect(),
    }
}

fn scan_fixture(state: SemanticFixture) -> ScanPhaseModel {
    let richness = state.richness();
    ScanPhaseModel {
        scope: "fixture/**/*.rs".to_string(),
        plan: "deterministic fixture".to_string(),
        attempt: (richness >= 2).then(|| fixture_scan_attempt(richness, state)),
        engine_outcomes: fixture_engine_outcomes(richness, state),
        empty_hint: (richness == 0).then_some("fixture empty".to_string()),
        live: None,
    }
}

fn fixture_scan_attempt(richness: usize, state: SemanticFixture) -> ScanAttemptModel {
    ScanAttemptModel {
        attempt_id: Some("attempt-test".to_string()),
        run_id: "run-test".to_string(),
        run_refs: vec!["run-test".to_string()],
        outcome: outcome_label(state).to_string(),
        disposition: "selected".to_string(),
        freshness: "current".to_string(),
        findings: Some(1),
        findings_added: (richness >= 3).then_some(1),
        findings_updated: Some(0),
        severity_counts: (richness >= 3)
            .then(|| vec![("high".to_string(), 1)])
            .unwrap_or_default(),
        artifact_count: usize::from(richness >= 3),
        artifact_paths: Vec::new(),
        duration_secs: Some(1),
        cost_usd: Some(0.0),
        cost_complete: Some(true),
        error: None,
    }
}

fn fixture_engine_outcomes(richness: usize, state: SemanticFixture) -> Vec<ScanEngineOutcomeModel> {
    (richness >= 1)
        .then(|| ScanEngineOutcomeModel {
            engine: "fixture-engine".to_string(),
            tool_key: None,
            outcome: outcome_label(state).to_string(),
            run_ref: Some("run-test".to_string()),
            detail: Some("hydrated".to_string()),
        })
        .into_iter()
        .collect()
}

fn outcome_label(state: SemanticFixture) -> &'static str {
    if state == SemanticFixture::Blocked {
        "blocked"
    } else {
        "completed"
    }
}

fn review_fixture(state: SemanticFixture) -> ReviewPhaseModel {
    let richness = state.richness();
    ReviewPhaseModel {
        review: fixture_review_queue(richness > 0),
        finding: (richness >= 1).then(fixture_finding),
        selection_disclosure: None,
        next_plan: crate::ui_view_models::NextScansState::Pending,
        chains: None,
    }
}

fn prove_fixture(state: SemanticFixture) -> ProvePhaseModel {
    let richness = state.richness();
    ProvePhaseModel {
        deferral: None,
        finding: (richness >= 1).then(fixture_finding),
        attack_path: fixture_attack_path(richness >= 1),
        proof: (richness >= 2).then(|| fixture_proof(state == SemanticFixture::Stale)),
        selection_disclosure: None,
        investigation: None,
        trace: None,
        empty_hint: (richness == 0).then_some("fixture empty".to_string()),
    }
}

fn fixture_attack_path(present: bool) -> TaintFlowPath {
    if !present {
        return TaintFlowPath {
            empty_hint: Some("fixture empty".to_string()),
            ..Default::default()
        };
    }
    TaintFlowPath {
        cwe: "CWE-79".to_string(),
        severity: "high".to_string(),
        stages: vec![TaintStageModel {
            title: "入力 → sink".to_string(),
            location: "src/lib.rs:1".to_string(),
            snippet: Some("fixture".to_string()),
        }],
        empty_hint: None,
    }
}

fn fix_fixture(state: SemanticFixture) -> FixPhaseModel {
    let richness = state.richness();
    FixPhaseModel {
        findings: fixture_findings(),
        review: fixture_review_queue(richness > 0),
        attack_tree: Default::default(),
        dfd: fixture_dfd(richness >= 2),
        finding: (richness >= 1).then(fixture_finding),
        selection_disclosure: None,
        patch: None,
        remediation: fixture_remediation(state),
        threat_patch: None,
        report: fixture_report(),
        export_command: "findings export --format json".to_string(),
    }
}
