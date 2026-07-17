//! Per-phase task preselection. Given the detected target kind and the rows
//! for a phase, decide which tasks to pre-check when that phase's picker opens.
//!
//! This is the deterministic, target-aware backbone the phase walker consumes;
//! a session-model refinement layers on top of the same task set (it can only
//! add/remove from this recommendation, never invent tasks).

use super::task_id::PlanningTaskId;
use super::task_row::{ArtifactState, PlanningTaskRow};
pub use kuzushi_core::repository_inventory::TargetProfile;
use kuzushi_core::{TargetKind, WorkflowPhase};
use std::collections::BTreeSet;
use std::path::Path;

/// The tasks to pre-check for `phase`, given the target kind. Rows whose
/// required CLI is missing are never recommended (they can't run).
pub fn recommended_tasks_for_phase(
    phase: WorkflowPhase,
    target: TargetProfile,
    rows: &[PlanningTaskRow],
) -> BTreeSet<PlanningTaskId> {
    rows.iter()
        .filter(|row| row.id.phase() == phase)
        .filter(|row| row.cli_available)
        .filter(|row| should_preselect(row, target))
        .map(|row| row.id)
        .collect()
}

pub fn applicable_tasks_for_phase(
    phase: WorkflowPhase,
    target: TargetProfile,
) -> Vec<PlanningTaskId> {
    PlanningTaskId::in_phase(phase)
        .into_iter()
        .filter(|task| task_applies_to_target(*task, target))
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

fn should_preselect(row: &PlanningTaskRow, target: TargetProfile) -> bool {
    use PlanningTaskId::*;
    match row.id {
        // 組 KUMI-KATA · map — foundational artifacts when not already cached.
        AttachFiles => false,
        GatherRepoContext | MapEntryPoints => missing_artifact(row),
        // Keep first value fast and predictable. These remain visible as
        // deliberate Deep map work instead of silently starting database or
        // model-backed construction from the default plan.
        BuildStrideThreatModel | BuildCodePropertyGraph | BuildCodeQlDatabase => false,
        // Reverse-engineering artifacts only matter for binary/APK targets.
        BuildXRay => target.kind.is_reverse_engineering_target() && missing_artifact(row),
        ReverseEngineerBinary => {
            target.kind.is_reverse_engineering_target() && target.has_reverse_engineering_artifact
        }
        // Specialized / second-methodology builds are opt-in.
        BuildPastaThreatModel | ThreatIntelCves => false,
        // Scan source surfaces; specialized systems hunts
        // are visible only when `task_applies_to_target` found matching code.
        ScanSecrets => true,
        ScanSemgrep => source_like(target.kind),
        // Deep/model-backed hunts stay opt-in. CodeQL in particular needs a
        // compatible database/build plan; CLI presence alone is not proof.
        ScanCodeql | ScanAgenticSast | HuntTaint => false,
        HuntThreatModel => true,
        HuntSystems => false,
        HuntUseAfterFree => target.has_c_family_source && target.has_compile_commands,
        // Review and Prove default to processing whatever the scan found.
        TriageFindings | VerifyFindings => true,
        // 掛 KAKE · fix — always report; patching is a deliberate opt-in.
        BuildReport => true,
        PatchFindings => false,
    }
}

fn task_applies_to_target(task: PlanningTaskId, target: TargetProfile) -> bool {
    use PlanningTaskId::*;
    match task {
        BuildXRay | ReverseEngineerBinary => target.kind.is_reverse_engineering_target(),
        HuntSystems => target.has_systems_surface(),
        HuntUseAfterFree => target.has_c_family_source,
        _ => true,
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

pub(crate) fn has_compile_commands_json(target: &Path) -> bool {
    kuzushi_core::repository_inventory::target_has_compile_commands(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn rows_for(phase: WorkflowPhase) -> Vec<PlanningTaskRow> {
        PlanningTaskId::in_phase(phase)
            .into_iter()
            .map(|task| {
                let mut row = PlanningTaskRow::for_task(task, Path::new("/nonexistent-target"));
                row.cli_available = true;
                row.blocker = None;
                row
            })
            .collect()
    }

    fn profile(kind: TargetKind) -> TargetProfile {
        TargetProfile {
            kind,
            has_reverse_engineering_artifact: kind.is_reverse_engineering_target(),
            ..TargetProfile::conservative()
        }
    }

    fn c_profile() -> TargetProfile {
        TargetProfile {
            kind: TargetKind::Source,
            has_c_family_source: true,
            has_rust_source: false,
            has_compile_commands: true,
            has_reverse_engineering_artifact: false,
        }
    }

    fn rust_profile() -> TargetProfile {
        TargetProfile {
            kind: TargetKind::Source,
            has_c_family_source: false,
            has_rust_source: true,
            has_compile_commands: false,
            has_reverse_engineering_artifact: false,
        }
    }

    #[test]
    fn map_defaults_to_quick_first_value_for_a_fresh_source_target() {
        let rows = rows_for(WorkflowPhase::Map);
        let picked =
            recommended_tasks_for_phase(WorkflowPhase::Map, profile(TargetKind::Source), &rows);
        assert!(picked.contains(&PlanningTaskId::GatherRepoContext));
        assert!(picked.contains(&PlanningTaskId::MapEntryPoints));
        assert!(!picked.contains(&PlanningTaskId::BuildStrideThreatModel));
        assert!(!picked.contains(&PlanningTaskId::BuildCodePropertyGraph));
        assert!(!picked.contains(&PlanningTaskId::BuildCodeQlDatabase));
        // No reverse-engineering on a plain source tree.
        assert!(!picked.contains(&PlanningTaskId::ReverseEngineerBinary));
        // PASTA / threat-intel stay opt-in.
        assert!(!picked.contains(&PlanningTaskId::BuildPastaThreatModel));
    }

    #[test]
    fn map_keeps_legacy_reverse_engineering_out_of_the_apk_picker() {
        let rows = rows_for(WorkflowPhase::Map);
        let picked =
            recommended_tasks_for_phase(WorkflowPhase::Map, profile(TargetKind::AndroidApk), &rows);
        assert!(!picked.contains(&PlanningTaskId::ReverseEngineerBinary));
        assert!(picked.contains(&PlanningTaskId::BuildXRay));
    }

    #[test]
    fn scan_keeps_legacy_uaf_out_of_source_pickers() {
        let rows = rows_for(WorkflowPhase::Scan);
        let c_source = recommended_tasks_for_phase(WorkflowPhase::Scan, c_profile(), &rows);
        assert!(!c_source.contains(&PlanningTaskId::HuntUseAfterFree));
        assert!(c_source.contains(&PlanningTaskId::ScanSecrets));

        let source =
            recommended_tasks_for_phase(WorkflowPhase::Scan, profile(TargetKind::Source), &rows);
        assert!(!source.contains(&PlanningTaskId::HuntUseAfterFree));
        assert!(source.contains(&PlanningTaskId::ScanSecrets));
        assert!(source.contains(&PlanningTaskId::ScanSemgrep));
        assert!(!source.contains(&PlanningTaskId::ScanCodeql));
        assert!(!source.contains(&PlanningTaskId::ScanAgenticSast));
        assert!(!source.contains(&PlanningTaskId::HuntTaint));
    }

    #[test]
    fn scan_does_not_preselect_uaf_without_compile_commands() {
        let rows = rows_for(WorkflowPhase::Scan);
        let mut c_source = c_profile();
        c_source.has_compile_commands = false;
        let picked = recommended_tasks_for_phase(WorkflowPhase::Scan, c_source, &rows);
        assert!(!picked.contains(&PlanningTaskId::HuntUseAfterFree));
        assert!(!applicable_tasks_for_phase(WorkflowPhase::Scan, c_source)
            .contains(&PlanningTaskId::HuntUseAfterFree));
    }

    #[test]
    fn scan_phase_hides_c_specific_rows_without_c_family_source() {
        let source = applicable_tasks_for_phase(WorkflowPhase::Scan, profile(TargetKind::Source));
        assert!(!source.contains(&PlanningTaskId::HuntUseAfterFree));
        assert!(!source.contains(&PlanningTaskId::HuntSystems));

        let rust = applicable_tasks_for_phase(WorkflowPhase::Scan, rust_profile());
        assert!(!rust.contains(&PlanningTaskId::HuntUseAfterFree));
        assert!(rust.contains(&PlanningTaskId::HuntSystems));

        let c_source = applicable_tasks_for_phase(WorkflowPhase::Scan, c_profile());
        assert!(!c_source.contains(&PlanningTaskId::HuntUseAfterFree));
        assert!(c_source.contains(&PlanningTaskId::HuntSystems));
    }

    #[test]
    fn review_defaults_to_triage() {
        let rows = rows_for(WorkflowPhase::Review);
        let picked =
            recommended_tasks_for_phase(WorkflowPhase::Review, profile(TargetKind::Source), &rows);
        assert!(picked.contains(&PlanningTaskId::TriageFindings));
        assert!(!picked.contains(&PlanningTaskId::VerifyFindings));
    }

    #[test]
    fn prove_defaults_to_verification() {
        let rows = rows_for(WorkflowPhase::Prove);
        let picked =
            recommended_tasks_for_phase(WorkflowPhase::Prove, profile(TargetKind::Source), &rows);
        assert!(picked.contains(&PlanningTaskId::VerifyFindings));
        assert!(!picked.contains(&PlanningTaskId::TriageFindings));
    }

    #[test]
    fn fix_reports_but_does_not_auto_patch() {
        let rows = rows_for(WorkflowPhase::Fix);
        let picked =
            recommended_tasks_for_phase(WorkflowPhase::Fix, profile(TargetKind::Source), &rows);
        assert!(picked.contains(&PlanningTaskId::BuildReport));
        assert!(!picked.contains(&PlanningTaskId::PatchFindings));
    }
}
