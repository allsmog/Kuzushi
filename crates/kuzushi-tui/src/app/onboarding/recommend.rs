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

pub const DECOMPOSE_FIRST_FILE_THRESHOLD: u64 = 20_000;

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
    if let Some(preselect) = ledger_preselect(row) {
        return preselect;
    }
    use PlanningTaskId::*;
    match row.id {
        // 組 KUMI-KATA · map — foundational artifacts when not already cached.
        AttachFiles => false,
        GatherRepoContext | MapEntryPoints => missing_artifact(row),
        // Decomposition is the honest first move on big monorepos, but the
        // deterministic profile cannot see repo size here — the Map page's
        // decompose-first card carries that signal; the row stays opt-in.
        DecomposeModules => false,
        // Keep first value fast and predictable. These remain visible as
        // deliberate Deep map work instead of silently starting database or
        // model-backed construction from the default plan.
        BuildThreatModel
        | BuildStrideThreatModel
        | BuildCodePropertyGraph
        | BuildCodeQlDatabase => false,
        // Reverse-engineering artifacts only matter for binary/APK targets.
        BuildXRay => target.kind.is_reverse_engineering_target() && missing_artifact(row),
        ReverseEngineerBinary => {
            target.kind.is_reverse_engineering_target() && target.has_reverse_engineering_artifact
        }
        // Specialized / second-methodology builds are opt-in. Harness
        // authoring spends model dollars and needs an engine checkout.
        BuildPastaThreatModel | ThreatIntelCves | MapFuzzAuthor => false,
        // The model-backed hunts ARE the Scan phase's value: agentic SAST and
        // the threat-model-driven hunt are pre-checked; deterministic
        // scanners are quick add-ons the operator opts into.
        ScanAgenticSast | HuntThreatModel => true,
        ScanSecrets | ScanSemgrep => false,
        // CodeQL needs a compatible database/build plan; CLI presence alone
        // is not proof. Taint needs a CPG build first.
        ScanCodeql | HuntTaint => false,
        HuntSystems => false,
        // Fuzzing lanes run the external engine for many minutes — deliberate
        // opt-in (sweep/differential also assume fuzz:run built targets first).
        ScanFuzz | ScanFuzzSweep | ScanFuzzDifferential => false,
        HuntUseAfterFree => target.has_c_family_source && target.has_compile_commands,
        // Review and Prove default to processing whatever the scan found.
        TriageFindings | VerifyFindings => true,
        // Corpus dedupe and chain composition are deliberate opt-ins:
        // both spend model dollars over the whole ledger.
        DedupeFindings | HuntChains => false,
        // 掛 KAKE · fix — always report; patching is a deliberate opt-in.
        BuildReport => true,
        PatchFindings => false,
    }
}

/// Item 5b: reality-aware pre-check overriding the static table. A FAILED- or
/// PARTIAL-but-resumable attempt is pre-checked so Enter continues it from
/// its checkpoint; an action task that already completed this pass is never
/// silently re-checked (the static table would invert both).
fn ledger_preselect(row: &PlanningTaskRow) -> Option<bool> {
    use super::task_row::LastAttempt;
    match &row.last_attempt {
        Some(LastAttempt::Failed { .. } | LastAttempt::Partial { .. }) => Some(true),
        Some(LastAttempt::Completed) if matches!(row.artifact_state, ArtifactState::Action) => {
            Some(false)
        }
        _ => None,
    }
}

pub(crate) fn large_repository_needs_decomposition(
    files_indexed: Option<u64>,
    target: Option<&Path>,
) -> bool {
    let Some(target) = target else {
        return false;
    };
    if files_indexed.unwrap_or_default() < DECOMPOSE_FIRST_FILE_THRESHOLD {
        return false;
    }
    kuzushi_core::load_nested_project_scopes(target)
        .ok()
        .flatten()
        .is_none_or(|tree| tree.non_root_scopes().next().is_none())
}

fn task_applies_to_target(task: PlanningTaskId, target: TargetProfile) -> bool {
    use PlanningTaskId::*;
    match task {
        BuildXRay | ReverseEngineerBinary => target.kind.is_reverse_engineering_target(),
        HuntSystems => target.has_systems_surface(),
        // The engine compiles C/C++ libFuzzer harnesses; other estates have
        // nothing for it to build or fuzz.
        HuntUseAfterFree | ScanFuzz | ScanFuzzSweep | ScanFuzzDifferential | MapFuzzAuthor => {
            target.has_c_family_source
        }
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
        assert!(!picked.contains(&PlanningTaskId::BuildThreatModel));
        assert!(!picked.contains(&PlanningTaskId::BuildCodePropertyGraph));
        assert!(!picked.contains(&PlanningTaskId::BuildCodeQlDatabase));
        // No reverse-engineering on a plain source tree.
        assert!(!picked.contains(&PlanningTaskId::ReverseEngineerBinary));
        // Threat-intel stays opt-in.
        assert!(!picked.contains(&PlanningTaskId::ThreatIntelCves));
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
        assert!(c_source.contains(&PlanningTaskId::ScanAgenticSast));

        let source =
            recommended_tasks_for_phase(WorkflowPhase::Scan, profile(TargetKind::Source), &rows);
        assert!(!source.contains(&PlanningTaskId::HuntUseAfterFree));
        assert!(!source.contains(&PlanningTaskId::ScanCodeql));
        assert!(!source.contains(&PlanningTaskId::HuntTaint));
    }

    /// Item 10: the model-backed hunts are the Scan default; deterministic
    /// scanners are opt-in add-ons.
    #[test]
    fn scan_defaults_to_model_backed_hunts_with_deterministic_addons_unchecked() {
        let rows = rows_for(WorkflowPhase::Scan);
        let picked =
            recommended_tasks_for_phase(WorkflowPhase::Scan, profile(TargetKind::Source), &rows);
        assert!(picked.contains(&PlanningTaskId::ScanAgenticSast));
        assert!(picked.contains(&PlanningTaskId::HuntThreatModel));
        assert!(!picked.contains(&PlanningTaskId::ScanSecrets));
        assert!(!picked.contains(&PlanningTaskId::ScanSemgrep));
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
        assert!(!source.contains(&PlanningTaskId::ScanFuzzSweep));
        assert!(!source.contains(&PlanningTaskId::ScanFuzzDifferential));

        let rust = applicable_tasks_for_phase(WorkflowPhase::Scan, rust_profile());
        assert!(!rust.contains(&PlanningTaskId::HuntUseAfterFree));
        assert!(rust.contains(&PlanningTaskId::HuntSystems));

        let c_source = applicable_tasks_for_phase(WorkflowPhase::Scan, c_profile());
        assert!(!c_source.contains(&PlanningTaskId::HuntUseAfterFree));
        assert!(c_source.contains(&PlanningTaskId::HuntSystems));
        assert!(c_source.contains(&PlanningTaskId::ScanFuzzSweep));
        assert!(c_source.contains(&PlanningTaskId::ScanFuzzDifferential));
    }

    /// The fuzz lanes are journey-visible on C-family targets but never
    /// preselected: they assume fuzz:run already built targets and spend
    /// real engine minutes.
    #[test]
    fn fuzz_lane_tasks_are_visible_opt_ins_on_c_targets() {
        let rows = rows_for(WorkflowPhase::Scan);
        let picked = recommended_tasks_for_phase(WorkflowPhase::Scan, c_profile(), &rows);
        assert!(!picked.contains(&PlanningTaskId::ScanFuzz));
        assert!(!picked.contains(&PlanningTaskId::ScanFuzzSweep));
        assert!(!picked.contains(&PlanningTaskId::ScanFuzzDifferential));
    }

    #[test]
    fn review_defaults_to_triage() {
        let rows = rows_for(WorkflowPhase::Review);
        let picked =
            recommended_tasks_for_phase(WorkflowPhase::Review, profile(TargetKind::Source), &rows);
        assert!(picked.contains(&PlanningTaskId::TriageFindings));
        assert!(!picked.contains(&PlanningTaskId::VerifyFindings));
        // Dedupe and chain-hunt are offered in the Review picker but never
        // preselected — both are deliberate model-spend opt-ins.
        let offered =
            applicable_tasks_for_phase(WorkflowPhase::Review, profile(TargetKind::Source));
        assert!(offered.contains(&PlanningTaskId::DedupeFindings));
        assert!(offered.contains(&PlanningTaskId::HuntChains));
        assert!(!picked.contains(&PlanningTaskId::DedupeFindings));
        assert!(!picked.contains(&PlanningTaskId::HuntChains));
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

    #[test]
    fn completed_and_failed_action_outcomes_invert_static_defaults() {
        let mut rows = rows_for(WorkflowPhase::Scan);
        let completed = rows
            .iter_mut()
            .find(|row| row.id == PlanningTaskId::ScanAgenticSast)
            .unwrap();
        completed.artifact_state = ArtifactState::Action;
        completed.last_attempt = Some(crate::app::LastAttempt::Completed);
        let failed = rows
            .iter_mut()
            .find(|row| row.id == PlanningTaskId::ScanSecrets)
            .unwrap();
        failed.artifact_state = ArtifactState::Action;
        failed.last_attempt = Some(crate::app::LastAttempt::Failed {
            resumable: false,
            resume_from: None,
        });

        let picked =
            recommended_tasks_for_phase(WorkflowPhase::Scan, profile(TargetKind::Source), &rows);

        assert!(!picked.contains(&PlanningTaskId::ScanAgenticSast));
        assert!(picked.contains(&PlanningTaskId::ScanSecrets));
    }

    #[test]
    fn partial_action_outcome_stays_pre_checked_like_a_failed_one() {
        let mut rows = rows_for(WorkflowPhase::Scan);
        let partial = rows
            .iter_mut()
            .find(|row| row.id == PlanningTaskId::ScanSecrets)
            .unwrap();
        partial.artifact_state = ArtifactState::Action;
        partial.last_attempt = Some(crate::app::LastAttempt::Partial {
            resumable: false,
            resume_from: None,
        });

        let picked =
            recommended_tasks_for_phase(WorkflowPhase::Scan, profile(TargetKind::Source), &rows);

        assert!(picked.contains(&PlanningTaskId::ScanSecrets));
    }
}
