use super::*;
use crate::ui_view_models::findings::FindingsPreviewModel;
use crate::ui_view_models::{
    DfdModel, FindingDetailModel, FindingEvidenceRow, FindingsEmptyState, FindingsModel,
    ReportPreviewCounts, ReportPreviewModel, ReviewQueueModel, SeverityCounts,
};
use std::sync::Arc;

pub(super) fn fixture_dfd(present: bool) -> DfdModel {
    DfdModel {
        empty_hint: (!present).then_some("fixture empty".to_string()),
        ..Default::default()
    }
}

pub(super) fn fixture_finding() -> FindingDetailModel {
    FindingDetailModel {
        alias: Some("F-001".to_string()),
        identity_label: "finding:test".to_string(),
        title: "Unicode boundary αβγ".to_string(),
        evidence: vec![FindingEvidenceRow {
            origin: "fixture".to_string(),
            header: "source → sink".to_string(),
            snippet: "untrusted_input()".to_string(),
            rationale: "deterministic evidence".to_string(),
            capture: None,
        }],
        ..Default::default()
    }
}

pub(super) fn fixture_proof(stale: bool) -> ProofReplayModel {
    ProofReplayModel {
        finding_alias: Some("F-001".to_string()),
        proof_level: 2,
        verdict: "verified".to_string(),
        backend: "fixture".to_string(),
        language: Some("rust".to_string()),
        harness_path: None,
        crash_evidence: Some("deterministic proof".to_string()),
        duration_ms: 1,
        cost_usd: 0.0,
        notes: Vec::new(),
        stages: None,
        created_at: "2026-07-14T00:00:00Z".to_string(),
        provenance_run_id: Some("run-proof".to_string()),
        replay_run_id: Some("run-proof".to_string()),
        requires_revalidation: stale,
    }
}

pub(super) fn fixture_review_queue(populated: bool) -> ReviewQueueModel {
    let count = usize::from(populated);
    ReviewQueueModel {
        navigation_active: false,
        refresh_status: None,
        decision_save_label: None,
        page: None,
        partial_load: None,
        total_count: count,
        visible_count: count,
        open_count: count,
        complete_count: 0,
        search_active: false,
        search_capture: false,
        active_filter_chips: vec!["completeness:all".to_string()],
        facet_groups: Arc::from([]),
        filter_label: "all".to_string(),
        completeness_mode: "all",
        ordering_indicator: None,
        operator_calibration: Default::default(),
        header: format!("{count} fixture findings"),
        empty_reason: (!populated).then_some("fixture empty".to_string()),
        rows: Arc::from([]),
        selected_row: None,
    }
}

pub(super) fn fixture_findings() -> FindingsModel {
    FindingsModel {
        total: 0,
        triaged: 0,
        pending: 0,
        counts: SeverityCounts::default(),
        header: "0 findings".to_string(),
        reconciliation_header: "fixture".to_string(),
        cursor: 0,
        empty: empty_findings(),
        selected_out_of_window: None,
        rows: Vec::new(),
        preview: FindingsPreviewModel {
            header: "fixture".to_string(),
            rows: Vec::new(),
            overflow: None,
        },
    }
}

fn empty_findings() -> FindingsEmptyState {
    FindingsEmptyState {
        hint: "fixture empty",
        ledger: "fixture".to_string(),
        context_cta: None,
        filtered_out: None,
        clean_scan: None,
    }
}

pub(super) fn fixture_remediation(state: SemanticFixture) -> RemediationLifecycleModel {
    RemediationLifecycleModel {
        load_state: remediation_load_state(state),
        stage: remediation_stage(state),
        application_id: None,
        patch_run_id: None,
        diff_hash: None,
        touched_paths: remediation_paths(state.richness()),
        reverify_run_id: None,
        detail: Some("fixture lifecycle".to_string()),
        updated_at: Some("2026-07-14T00:00:00Z".to_string()),
        reverify_command: Some("verify F-001".to_string()),
        reverify_control_hint: Some("Esc then v".to_string()),
        load_error: None,
    }
}

fn remediation_load_state(state: SemanticFixture) -> RemediationLoadState {
    if state == SemanticFixture::Empty {
        RemediationLoadState::Missing
    } else {
        RemediationLoadState::Ready
    }
}

fn remediation_stage(state: SemanticFixture) -> RemediationLifecycleStage {
    match state {
        SemanticFixture::Empty => RemediationLifecycleStage::NotDrafted,
        SemanticFixture::Stale => RemediationLifecycleStage::ChangedSinceApply,
        SemanticFixture::Blocked => RemediationLifecycleStage::ApplyFailed,
        _ => RemediationLifecycleStage::DraftAvailable,
    }
}

fn remediation_paths(richness: usize) -> Vec<String> {
    if richness >= 2 {
        vec!["src/認証/really-long-remediation-target.rs".to_string()]
    } else {
        Vec::new()
    }
}

pub(super) fn fixture_report() -> ReportPreviewModel {
    ReportPreviewModel {
        format: "json".to_string(),
        completeness: "all",
        target: "fixture".to_string(),
        latest_run_id: None,
        generated_at: "2026-07-14T00:00:00Z".to_string(),
        preview_metadata: "fixture",
        counts: ReportPreviewCounts::default(),
        omitted_fields: Vec::new(),
        rows: Vec::new(),
    }
}
