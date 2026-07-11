use super::{FixPhaseModel, HuntPhaseModel};
use crate::ui_view_models::{
    active_review_queue_mode, attack_tree, cached_findings_heatmap_with_selection,
    current_finding_for_detail, dfd_model, findings_model, patch_review_model,
    report_preview_model, review_queue_model, selected_finding_detail_model, source_tree_model,
    strategy_queue_model, threat_patch_card_model, workbench_report_command,
};
use crate::ShellApp;
use kuzushi_core::WorkspaceExportFormat;

pub(super) fn hunt_phase_model(app: &ShellApp) -> HuntPhaseModel {
    let selected = current_finding_for_detail(app).map(|(_, finding)| finding);
    HuntPhaseModel {
        source: source_tree_model(app),
        strategy: strategy_queue_model(app),
        review: review_queue_model(app, active_review_queue_mode(app)),
        heatmap: cached_findings_heatmap_with_selection(app, selected.as_ref()),
    }
}

pub(super) fn fix_phase_model(app: &ShellApp) -> FixPhaseModel {
    let mode = active_review_queue_mode(app);
    let finding = selected_finding_detail_model(app);
    let patch = finding
        .as_ref()
        .and_then(|finding| finding.alias.as_deref())
        .and_then(|alias| patch_review_model(app, alias));
    FixPhaseModel {
        findings: findings_model(app),
        review: review_queue_model(app, mode),
        attack_tree: attack_tree(app),
        dfd: dfd_model(app),
        finding,
        patch,
        threat_patch: threat_patch_card_model(app),
        report: report_preview_model(app, WorkspaceExportFormat::Sarif, mode),
        export_command: workbench_report_command(mode).into_owned(),
    }
}
