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
use std::path::{Path, PathBuf};

const SOURCE_SCAN_FILE_BUDGET: usize = 20_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetProfile {
    pub kind: TargetKind,
    pub has_c_family_source: bool,
    pub has_rust_source: bool,
}

impl TargetProfile {
    pub fn detect(target: &Path, kind: TargetKind) -> Self {
        let source = detect_systems_source(target);
        Self {
            kind,
            has_c_family_source: source.has_c_family_source,
            has_rust_source: source.has_rust_source,
        }
    }

    #[cfg(test)]
    fn source_only(kind: TargetKind) -> Self {
        Self {
            kind,
            has_c_family_source: false,
            has_rust_source: false,
        }
    }

    fn has_systems_surface(self) -> bool {
        self.kind == TargetKind::NativeBinary || self.has_c_family_source || self.has_rust_source
    }
}

#[derive(Default)]
struct SystemsSourceEvidence {
    has_c_family_source: bool,
    has_rust_source: bool,
}

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
        GatherRepoContext
        | MapEntryPoints
        | BuildStrideThreatModel
        | BuildCodePropertyGraph
        | BuildCodeQlDatabase => missing_artifact(row),
        // Reverse-engineering artifacts only matter for binary/APK targets.
        BuildXRay => target.kind.is_reverse_engineering_target() && missing_artifact(row),
        ReverseEngineerBinary => target.kind.is_reverse_engineering_target(),
        // Specialized / second-methodology builds are opt-in.
        BuildPastaThreatModel | ThreatIntelCves => false,
        // 崩 KUZUSHI · hunt — scan source surfaces; specialized systems hunts
        // are visible only when `task_applies_to_target` found matching code.
        ScanSecrets => true,
        ScanSemgrep | ScanCodeql | ScanAgenticSast | HuntTaint => source_like(target.kind),
        HuntThreatModel => true,
        HuntSystems => false,
        HuntUseAfterFree => target.has_c_family_source,
        // 作 TSUKURI · confirm — always triage then verify whatever was found.
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

fn detect_systems_source(target: &Path) -> SystemsSourceEvidence {
    let mut evidence = SystemsSourceEvidence::default();
    let mut stack = vec![target.to_path_buf()];
    let mut budget = SOURCE_SCAN_FILE_BUDGET;
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if budget == 0 || systems_source_complete(&evidence) {
                return evidence;
            }
            budget -= 1;
            absorb_source_entry(&entry.path(), &mut evidence, &mut stack);
        }
    }
    evidence
}

fn absorb_source_entry(
    path: &Path,
    evidence: &mut SystemsSourceEvidence,
    stack: &mut Vec<PathBuf>,
) {
    if path.is_dir() {
        if !is_skippable_source_dir(path) {
            stack.push(path.to_path_buf());
        }
        return;
    }
    note_source_extension(path, evidence);
}

fn note_source_extension(path: &Path, evidence: &mut SystemsSourceEvidence) {
    let Some(ext) = path.extension().and_then(|ext| ext.to_str()) else {
        return;
    };
    match ext.to_ascii_lowercase().as_str() {
        "c" | "cc" | "cpp" | "cxx" | "h" | "hh" | "hpp" | "hxx" | "ipp" | "cu" | "cuh" => {
            evidence.has_c_family_source = true;
        }
        "rs" => evidence.has_rust_source = true,
        _ => {}
    }
}

fn systems_source_complete(evidence: &SystemsSourceEvidence) -> bool {
    evidence.has_c_family_source && evidence.has_rust_source
}

fn is_skippable_source_dir(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some(".git" | "node_modules" | ".kuzushi" | "target" | "vendor")
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

    fn profile(kind: TargetKind) -> TargetProfile {
        TargetProfile::source_only(kind)
    }

    fn c_profile() -> TargetProfile {
        TargetProfile {
            kind: TargetKind::Source,
            has_c_family_source: true,
            has_rust_source: false,
        }
    }

    fn rust_profile() -> TargetProfile {
        TargetProfile {
            kind: TargetKind::Source,
            has_c_family_source: false,
            has_rust_source: true,
        }
    }

    #[test]
    fn map_preselects_context_for_a_fresh_source_target() {
        let rows = rows_for(WorkflowPhase::Map);
        let picked =
            recommended_tasks_for_phase(WorkflowPhase::Map, profile(TargetKind::Source), &rows);
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
        let picked =
            recommended_tasks_for_phase(WorkflowPhase::Map, profile(TargetKind::AndroidApk), &rows);
        assert!(picked.contains(&PlanningTaskId::ReverseEngineerBinary));
        assert!(picked.contains(&PlanningTaskId::BuildXRay));
    }

    #[test]
    fn hunt_scopes_uaf_to_c_family_source() {
        let rows = rows_for(WorkflowPhase::Hunt);
        let c_source = recommended_tasks_for_phase(WorkflowPhase::Hunt, c_profile(), &rows);
        assert!(c_source.contains(&PlanningTaskId::HuntUseAfterFree));
        assert!(c_source.contains(&PlanningTaskId::ScanSecrets));

        let source =
            recommended_tasks_for_phase(WorkflowPhase::Hunt, profile(TargetKind::Source), &rows);
        assert!(!source.contains(&PlanningTaskId::HuntUseAfterFree));
        assert!(source.contains(&PlanningTaskId::ScanAgenticSast));
    }

    #[test]
    fn hunt_phase_hides_c_specific_rows_without_c_family_source() {
        let source = applicable_tasks_for_phase(WorkflowPhase::Hunt, profile(TargetKind::Source));
        assert!(!source.contains(&PlanningTaskId::HuntUseAfterFree));
        assert!(!source.contains(&PlanningTaskId::HuntSystems));

        let rust = applicable_tasks_for_phase(WorkflowPhase::Hunt, rust_profile());
        assert!(!rust.contains(&PlanningTaskId::HuntUseAfterFree));
        assert!(rust.contains(&PlanningTaskId::HuntSystems));

        let c_source = applicable_tasks_for_phase(WorkflowPhase::Hunt, c_profile());
        assert!(c_source.contains(&PlanningTaskId::HuntUseAfterFree));
        assert!(c_source.contains(&PlanningTaskId::HuntSystems));
    }

    #[test]
    fn confirm_always_triages_and_verifies() {
        let rows = rows_for(WorkflowPhase::Confirm);
        let picked =
            recommended_tasks_for_phase(WorkflowPhase::Confirm, profile(TargetKind::Source), &rows);
        assert!(picked.contains(&PlanningTaskId::TriageFindings));
        assert!(picked.contains(&PlanningTaskId::VerifyFindings));
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
