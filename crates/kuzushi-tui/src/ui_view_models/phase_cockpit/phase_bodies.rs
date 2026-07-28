use super::{
    FixPhaseModel, RemediationLifecycleModel, RemediationLifecycleStage, RemediationLoadState,
    ReviewPhaseModel, SelectionDisclosureModel,
};
use crate::ui_view_models::{
    active_review_queue_mode, attack_tree, current_finding_for_detail, dfd_model,
    finding_detail_model_for_projection, findings_model, patch_review_model, report_preview_model,
    review_queue_model, selected_finding_detail_model, selected_finding_out_of_window_notice,
    threat_patch_card_model, visible_finding_at_cursor, workbench_report_command,
};
use crate::ShellApp;
use crate::{FindingPatchTruthState, ViewDataState};
use kuzushi_core::{PatchLifecycleRecord, PatchLifecycleState, WorkspaceExportFormat};

pub(super) fn review_phase_model(app: &ShellApp) -> ReviewPhaseModel {
    let finding = visible_finding_at_cursor(app)
        .map(|(alias, finding)| finding_detail_model_for_projection(app, Some(alias), &finding));
    ReviewPhaseModel {
        review: review_queue_model(app, active_review_queue_mode(app)),
        finding,
        selection_disclosure: review_selection_disclosure(app),
        next_plan: super::map::next_scans_state(app),
        chains: super::chain_artifacts::chain_artifacts_model(app),
    }
}

pub(super) fn fix_phase_model(app: &ShellApp) -> FixPhaseModel {
    let mode = active_review_queue_mode(app);
    let findings = findings_model(app);
    let finding = selected_finding_detail_model(app);
    let patch = finding
        .as_ref()
        .and_then(|finding| finding.alias.as_deref())
        .and_then(|alias| patch_review_model(app, alias));
    let remediation_finding = current_finding_for_detail(app).map(|(_, finding)| finding);
    let mut remediation =
        remediation_lifecycle_model(app, remediation_finding.as_ref(), patch.is_some());
    if remediation.reverify_command.is_some() {
        remediation.reverify_control_hint =
            Some(crate::ui_view_models::workbench_reverify_control_hint(app));
    }
    FixPhaseModel {
        selection_disclosure: actionable_selection_disclosure(app, &findings, finding.as_ref()),
        findings,
        review: review_queue_model(app, mode),
        attack_tree: attack_tree(app),
        dfd: dfd_model(app),
        finding,
        patch,
        remediation,
        threat_patch: threat_patch_card_model(app),
        report: report_preview_model(app, WorkspaceExportFormat::Sarif, mode),
        export_command: workbench_report_command(mode).into_owned(),
    }
}

fn remediation_lifecycle_model(
    app: &ShellApp,
    finding: Option<&kuzushi_core::Finding>,
    staged: bool,
) -> RemediationLifecycleModel {
    let Some(finding) = finding else {
        return empty_remediation_model(RemediationLifecycleStage::NotDrafted);
    };
    let Some(target) = app.target() else {
        return empty_remediation_model(staged_stage(staged));
    };
    let target_revision = app
        .engagement
        .phase_target_snapshot()
        .and_then(|snapshot| snapshot.revision.as_deref());
    let state = app.workbench_cache().borrow().cached_finding_patch_truth(
        target,
        &finding.fingerprint,
        finding.scan_id.as_deref(),
        target_revision,
    );
    match state {
        ViewDataState::NotRequested | ViewDataState::Loading => remediation_loading_model(staged),
        ViewDataState::Ready(FindingPatchTruthState::Missing) => {
            let mut model = empty_remediation_model(staged_stage(staged));
            model.load_state = RemediationLoadState::Missing;
            model
        }
        ViewDataState::Ready(FindingPatchTruthState::Failed(error)) => {
            let mut model = empty_remediation_model(staged_stage(staged));
            model.load_state = RemediationLoadState::Failed;
            model.load_error = Some(format!("could not load remediation receipt: {error}"));
            model
        }
        ViewDataState::Ready(FindingPatchTruthState::Ready(truth)) => {
            remediation_model_from_truth(truth, staged)
        }
    }
}

fn remediation_loading_model(staged: bool) -> RemediationLifecycleModel {
    let mut model = empty_remediation_model(staged_stage(staged));
    model.load_state = RemediationLoadState::Loading;
    model
}

fn remediation_model_from_truth(
    truth: crate::app::FindingPatchTruth,
    staged: bool,
) -> RemediationLifecycleModel {
    if let Some(record) = truth.lifecycle {
        if !truth.lifecycle_matches_finding_generation {
            return prior_generation_remediation_model(record);
        }
        return remediation_model_from_record(record);
    }
    let Some(result) = truth.latest_result else {
        return empty_remediation_model(staged_stage(staged));
    };
    RemediationLifecycleModel {
        load_state: RemediationLoadState::Ready,
        stage: if staged {
            RemediationLifecycleStage::StagedForApproval
        } else {
            RemediationLifecycleStage::DraftAvailable
        },
        patch_run_id: Some(result.patch_run_id),
        detail: Some(format!("synthesis status {}", result.status.as_str())),
        ..empty_remediation_model(RemediationLifecycleStage::DraftAvailable)
    }
}

fn prior_generation_remediation_model(record: PatchLifecycleRecord) -> RemediationLifecycleModel {
    let mut model = remediation_model_from_record(record);
    model.stage = RemediationLifecycleStage::PriorFindingGeneration;
    model.detail = Some(
        "the finding was rediscovered in a newer scan; generate and verify remediation for the current observation"
            .to_string(),
    );
    model.reverify_command = None;
    model
}

fn remediation_model_from_record(record: PatchLifecycleRecord) -> RemediationLifecycleModel {
    let stage = lifecycle_stage(record.state);
    let touched_paths = record.touched_paths().map(str::to_string).collect();
    let reverify_command = should_offer_reverify(stage).then(|| {
        format!(
            "run patch:reverify {}",
            serde_json::json!({ "applicationId": record.application_id })
        )
    });
    RemediationLifecycleModel {
        load_state: RemediationLoadState::Ready,
        stage,
        application_id: Some(record.application_id),
        patch_run_id: Some(record.patch_run_id),
        diff_hash: Some(record.diff_hash),
        touched_paths,
        reverify_run_id: record.reverify_run_id,
        detail: record.detail,
        updated_at: Some(record.updated_at),
        reverify_command,
        reverify_control_hint: None,
        load_error: None,
    }
}

fn lifecycle_stage(state: PatchLifecycleState) -> RemediationLifecycleStage {
    match state {
        PatchLifecycleState::Applying => RemediationLifecycleStage::Applying,
        PatchLifecycleState::ApplyFailed => RemediationLifecycleStage::ApplyFailed,
        PatchLifecycleState::Applied => RemediationLifecycleStage::Applied,
        PatchLifecycleState::ReverifyRunning => RemediationLifecycleStage::ReverifyRunning,
        PatchLifecycleState::Verified => RemediationLifecycleStage::Verified,
        PatchLifecycleState::StillVulnerable => RemediationLifecycleStage::StillVulnerable,
        PatchLifecycleState::NotRediscovered => RemediationLifecycleStage::NotRediscovered,
        PatchLifecycleState::Inconclusive => RemediationLifecycleStage::Inconclusive,
        PatchLifecycleState::Failed => RemediationLifecycleStage::Failed,
        PatchLifecycleState::Interrupted => RemediationLifecycleStage::Interrupted,
        PatchLifecycleState::ChangedSinceApply => RemediationLifecycleStage::ChangedSinceApply,
    }
}

fn should_offer_reverify(stage: RemediationLifecycleStage) -> bool {
    !matches!(
        stage,
        RemediationLifecycleStage::NotDrafted
            | RemediationLifecycleStage::DraftAvailable
            | RemediationLifecycleStage::StagedForApproval
            | RemediationLifecycleStage::Applying
            | RemediationLifecycleStage::ApplyFailed
            | RemediationLifecycleStage::ReverifyRunning
            | RemediationLifecycleStage::Verified
            | RemediationLifecycleStage::PriorFindingGeneration
    )
}

fn staged_stage(staged: bool) -> RemediationLifecycleStage {
    if staged {
        RemediationLifecycleStage::StagedForApproval
    } else {
        RemediationLifecycleStage::NotDrafted
    }
}

fn empty_remediation_model(stage: RemediationLifecycleStage) -> RemediationLifecycleModel {
    RemediationLifecycleModel {
        load_state: RemediationLoadState::Ready,
        stage,
        application_id: None,
        patch_run_id: None,
        diff_hash: None,
        touched_paths: Vec::new(),
        reverify_run_id: None,
        detail: None,
        updated_at: None,
        reverify_command: None,
        reverify_control_hint: None,
        load_error: None,
    }
}

pub(super) fn review_selection_disclosure(app: &ShellApp) -> Option<SelectionDisclosureModel> {
    let notice = selected_finding_out_of_window_notice(app)?;
    Some(SelectionDisclosureModel {
        message: format!("{notice}; Review actions target the highlighted visible row"),
        filter: active_filter_label(app),
        reveal_command: "findings",
    })
}

pub(super) fn actionable_selection_disclosure(
    app: &ShellApp,
    findings: &crate::ui_view_models::FindingsModel,
    finding: Option<&crate::ui_view_models::FindingDetailModel>,
) -> Option<SelectionDisclosureModel> {
    findings.selected_out_of_window.as_ref()?;
    let finding = finding?;
    let reference = finding
        .alias
        .as_deref()
        .unwrap_or(finding.identity_label.as_str());
    Some(SelectionDisclosureModel {
        message: format!(
            "{reference} is pinned outside this projection; actions target this displayed finding"
        ),
        filter: active_filter_label(app),
        reveal_command: "findings",
    })
}

fn active_filter_label(app: &ShellApp) -> String {
    let search = app.router.workbench().review().search_query.trim();
    if !search.is_empty() {
        return format!("search:{search}");
    }
    app.active_findings_filter()
        .as_deref()
        .filter(|filter| !filter.trim().is_empty())
        .unwrap_or("component or loaded-list projection")
        .to_string()
}
