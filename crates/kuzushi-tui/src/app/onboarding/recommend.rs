//! Per-phase task preselection. Given the detected target kind and the rows
//! for a phase, decide which tasks to pre-check when that phase's picker opens.
//!
//! This is the deterministic, target-aware backbone the phase walker consumes;
//! a session-model refinement layers on top of the same task set (it can only
//! add/remove from this recommendation, never invent tasks).

use super::phase::WorkflowPhase;
use super::task_id::PlanningTaskId;
use super::task_row::{ArtifactState, PlanningTaskRow};
use kuzushi_core::TargetKind;
use std::collections::BTreeSet;

/// The tasks to pre-check for `phase`, given the target kind. Rows whose
/// required CLI is missing are never recommended (they can't run).
pub fn recommended_tasks_for_phase(
    phase: WorkflowPhase,
    target_kind: TargetKind,
    rows: &[PlanningTaskRow],
) -> BTreeSet<PlanningTaskId> {
    rows.iter()
        .filter(|row| row.id.phase() == phase)
        .filter(|row| row.cli_available)
        .filter(|row| should_preselect(row, target_kind))
        .map(|row| row.id)
        .collect()
}

/// The session-model-recommended tasks that belong to `phase` and are runnable
/// (a present, CLI-available row). Used to merge model recommendations into a
/// phase's preselection.
pub fn model_recommended_in_phase(
    model_tasks: &BTreeSet<PlanningTaskId>,
    rows: &[PlanningTaskRow],
    phase: WorkflowPhase,
) -> Vec<PlanningTaskId> {
    rows.iter()
        .filter(|row| row.id.phase() == phase && row.cli_available && model_tasks.contains(&row.id))
        .map(|row| row.id)
        .collect()
}

fn should_preselect(row: &PlanningTaskRow, kind: TargetKind) -> bool {
    use PlanningTaskId::*;
    match row.id {
        // 組 KUMI-KATA · map — foundational artifacts when not already cached.
        GatherRepoContext | MapEntryPoints | BuildStrideThreatModel | BuildCodePropertyGraph
        | BuildCodeQlDatabase => missing_artifact(row),
        // Reverse-engineering artifacts only matter for binary/APK targets.
        BuildXRay => kind.is_reverse_engineering_target() && missing_artifact(row),
        ReverseEngineerBinary => kind.is_reverse_engineering_target(),
        // Specialized / second-methodology builds are opt-in.
        BuildPastaThreatModel | ThreatIntelCves => false,
        // 崩 KUZUSHI · hunt — scan the source surface; UAF only for native code.
        ScanSecrets => true,
        ScanSemgrep | ScanCodeql | ScanAgenticSast | HuntTaint => source_like(kind),
        HuntThreatModel => true,
        HuntSystems => false,
        HuntUseAfterFree => matches!(kind, TargetKind::NativeBinary),
        // 作 TSUKURI · confirm — always triage then verify whatever was found.
        TriageFindings | VerifyFindings => true,
        // 掛 KAKE · fix — always report; patching is a deliberate opt-in.
        BuildReport => true,
        PatchFindings => false,
    }
}

/// A Map artifact task is worth preselecting only when it hasn't been built yet
/// (cached artifacts are reused, not rebuilt).
fn missing_artifact(row: &PlanningTaskRow) -> bool {
    matches!(
        row.artifact_state,
        ArtifactState::Missing | ArtifactState::Invalid
    )
}

fn source_like(kind: TargetKind) -> bool {
    matches!(
        kind,
        TargetKind::Source | TargetKind::JvmApp | TargetKind::AndroidApk
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn rows_for(phase: WorkflowPhase) -> Vec<PlanningTaskRow> {
        PlanningTaskId::in_phase(phase)
            .into_iter()
            .map(|task| PlanningTaskRow::for_task(task, Path::new("/nonexistent-target")))
            .collect()
    }

    #[test]
    fn map_preselects_context_for_a_fresh_source_target() {
        let rows = rows_for(WorkflowPhase::Map);
        let picked = recommended_tasks_for_phase(WorkflowPhase::Map, TargetKind::Source, &rows);
        assert!(picked.contains(&PlanningTaskId::GatherRepoContext));
        assert!(picked.contains(&PlanningTaskId::BuildStrideThreatModel));
        // No reverse-engineering on a plain source tree.
        assert!(!picked.contains(&PlanningTaskId::ReverseEngineerBinary));
        // PASTA / threat-intel stay opt-in.
        assert!(!picked.contains(&PlanningTaskId::BuildPastaThreatModel));
    }

    #[test]
    fn map_preselects_reverse_engineering_for_an_apk() {
        let rows = rows_for(WorkflowPhase::Map);
        let picked = recommended_tasks_for_phase(WorkflowPhase::Map, TargetKind::AndroidApk, &rows);
        assert!(picked.contains(&PlanningTaskId::ReverseEngineerBinary));
        assert!(picked.contains(&PlanningTaskId::BuildXRay));
    }

    #[test]
    fn hunt_scopes_uaf_to_native_targets() {
        let rows = rows_for(WorkflowPhase::Hunt);
        let native =
            recommended_tasks_for_phase(WorkflowPhase::Hunt, TargetKind::NativeBinary, &rows);
        assert!(native.contains(&PlanningTaskId::HuntUseAfterFree));
        assert!(native.contains(&PlanningTaskId::ScanSecrets));

        let source = recommended_tasks_for_phase(WorkflowPhase::Hunt, TargetKind::Source, &rows);
        assert!(!source.contains(&PlanningTaskId::HuntUseAfterFree));
        assert!(source.contains(&PlanningTaskId::ScanAgenticSast));
    }

    #[test]
    fn confirm_always_triages_and_verifies() {
        let rows = rows_for(WorkflowPhase::Confirm);
        let picked = recommended_tasks_for_phase(WorkflowPhase::Confirm, TargetKind::Source, &rows);
        assert!(picked.contains(&PlanningTaskId::TriageFindings));
        assert!(picked.contains(&PlanningTaskId::VerifyFindings));
    }

    #[test]
    fn fix_reports_but_does_not_auto_patch() {
        let rows = rows_for(WorkflowPhase::Fix);
        let picked = recommended_tasks_for_phase(WorkflowPhase::Fix, TargetKind::Source, &rows);
        assert!(picked.contains(&PlanningTaskId::BuildReport));
        assert!(!picked.contains(&PlanningTaskId::PatchFindings));
    }
}
