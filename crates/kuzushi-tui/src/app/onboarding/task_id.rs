use super::phase::WorkflowPhase;

/// Every task an operator can select across the four engagement phases. Each
/// variant maps to a concrete tool (or a tool + option) and, for the Map-phase
/// tasks that build reusable artifacts, an artifact path used for prior-run
/// detection. Hunt/Confirm/Fix tasks are actions (no cached artifact).
///
/// Ordering of variants is the canonical UI/run order, grouped by phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PlanningTaskId {
    // 組 KUMI-KATA · map — context & analysis artifacts.
    AttachFiles,
    GatherRepoContext,
    MapEntryPoints,
    BuildXRay,
    BuildStrideThreatModel,
    BuildPastaThreatModel,
    BuildCodePropertyGraph,
    BuildCodeQlDatabase,
    ThreatIntelCves,
    ReverseEngineerBinary,
    // 崩 KUZUSHI · hunt — find vulnerabilities.
    ScanSecrets,
    ScanSemgrep,
    ScanCodeql,
    ScanAgenticSast,
    HuntTaint,
    HuntThreatModel,
    HuntSystems,
    HuntUseAfterFree,
    // 作 TSUKURI · confirm — triage & verify.
    TriageFindings,
    VerifyFindings,
    // 掛 KAKE · fix — patch & report.
    PatchFindings,
    BuildReport,
}

impl PlanningTaskId {
    pub const ALL: &'static [PlanningTaskId] = &[
        PlanningTaskId::AttachFiles,
        PlanningTaskId::GatherRepoContext,
        PlanningTaskId::MapEntryPoints,
        PlanningTaskId::BuildXRay,
        PlanningTaskId::BuildStrideThreatModel,
        PlanningTaskId::BuildPastaThreatModel,
        PlanningTaskId::BuildCodePropertyGraph,
        PlanningTaskId::BuildCodeQlDatabase,
        PlanningTaskId::ThreatIntelCves,
        PlanningTaskId::ReverseEngineerBinary,
        PlanningTaskId::ScanSecrets,
        PlanningTaskId::ScanSemgrep,
        PlanningTaskId::ScanCodeql,
        PlanningTaskId::ScanAgenticSast,
        PlanningTaskId::HuntTaint,
        PlanningTaskId::HuntThreatModel,
        PlanningTaskId::HuntSystems,
        PlanningTaskId::HuntUseAfterFree,
        PlanningTaskId::TriageFindings,
        PlanningTaskId::VerifyFindings,
        PlanningTaskId::PatchFindings,
        PlanningTaskId::BuildReport,
    ];

    /// Tasks belonging to a single phase, in canonical order.
    pub fn in_phase(phase: WorkflowPhase) -> Vec<PlanningTaskId> {
        PlanningTaskId::ALL
            .iter()
            .copied()
            .filter(|task| task.phase() == phase)
            .collect()
    }

    pub fn phase(self) -> WorkflowPhase {
        use PlanningTaskId::*;
        match self {
            AttachFiles
            | GatherRepoContext
            | MapEntryPoints
            | BuildXRay
            | BuildStrideThreatModel
            | BuildPastaThreatModel
            | BuildCodePropertyGraph
            | BuildCodeQlDatabase
            | ThreatIntelCves
            | ReverseEngineerBinary => WorkflowPhase::Map,
            ScanSecrets | ScanSemgrep | ScanCodeql | ScanAgenticSast | HuntTaint
            | HuntThreatModel | HuntSystems | HuntUseAfterFree => WorkflowPhase::Hunt,
            TriageFindings | VerifyFindings => WorkflowPhase::Confirm,
            PatchFindings | BuildReport => WorkflowPhase::Fix,
        }
    }

    pub fn label(self) -> &'static str {
        use PlanningTaskId::*;
        match self {
            AttachFiles => "Attach reference files",
            GatherRepoContext => "Gather repo context",
            MapEntryPoints => "Map entry points",
            BuildXRay => "Build X-ray",
            BuildStrideThreatModel => "Build STRIDE threat model",
            BuildPastaThreatModel => "Build PASTA threat model",
            BuildCodePropertyGraph => "Build code property graph",
            BuildCodeQlDatabase => "Build CodeQL DB",
            ThreatIntelCves => "Threat intel (CVEs)",
            ReverseEngineerBinary => "Reverse-engineer binary",
            ScanSecrets => "Scan for secrets",
            ScanSemgrep => "Semgrep SAST scan",
            ScanCodeql => "CodeQL security scan",
            ScanAgenticSast => "Agentic SAST review",
            HuntTaint => "Taint dataflow hunt",
            HuntThreatModel => "Threat-model-driven hunt",
            HuntSystems => "Systems-level semantic hunt",
            HuntUseAfterFree => "Use-after-free hunt (C/C++)",
            TriageFindings => "Triage findings",
            VerifyFindings => "Verify exploitability",
            PatchFindings => "Patch findings",
            BuildReport => "Build report",
        }
    }

    /// Tool name dispatched when this task runs. STRIDE and PASTA share
    /// `threat-model:build` and differ only in their `methodology` input.
    pub fn tool_name(self) -> &'static str {
        use PlanningTaskId::*;
        match self {
            AttachFiles => "attach",
            GatherRepoContext => "context:build",
            MapEntryPoints => "entry-points:extract",
            BuildXRay => "x-ray:run",
            BuildStrideThreatModel | BuildPastaThreatModel => "threat-model:build",
            BuildCodePropertyGraph => "cpg:build",
            BuildCodeQlDatabase => "codeql:create-db",
            ThreatIntelCves => "threat-intel:discover",
            ReverseEngineerBinary => "pwn:reverse",
            ScanSecrets => "secret-scan:scan",
            ScanSemgrep => "semgrep:scan",
            ScanCodeql => "codeql:scan",
            ScanAgenticSast => "agentic-sast:scan",
            HuntTaint => "taint-iris-next:hunt",
            HuntThreatModel => "carlini-threat-hunt:run",
            HuntSystems => "systems-hunt:systems-hunt",
            HuntUseAfterFree => "uaf-hunt:hunt",
            TriageFindings => "triage:run",
            VerifyFindings => "verify:finding",
            PatchFindings => "patch:finding",
            BuildReport => "report:build",
        }
    }

    /// Whether the task requires an agent runtime. Used to surface a
    /// "model-backed" / "no model cost" hint next to each row.
    pub fn is_model_backed(self) -> bool {
        use PlanningTaskId::*;
        matches!(
            self,
            BuildXRay
                | BuildStrideThreatModel
                | BuildPastaThreatModel
                | ScanAgenticSast
                | HuntTaint
                | HuntThreatModel
                | HuntSystems
                | HuntUseAfterFree
                | TriageFindings
                | VerifyFindings
                | PatchFindings
        )
    }

    pub fn is_inline_action(self) -> bool {
        matches!(self, PlanningTaskId::AttachFiles)
    }

    pub fn dispatches_tool(self) -> bool {
        !self.is_inline_action()
    }

    /// Relative artifact path under the workspace root used to determine
    /// whether the task has already been run. `None` for action tasks
    /// (Hunt/Confirm/Fix and reverse-engineering) that don't cache a
    /// reusable artifact at a fixed path.
    pub fn artifact_relative_path(self) -> Option<&'static str> {
        use PlanningTaskId::*;
        let path = match self {
            GatherRepoContext => ".kuzushi/context-snapshot.json",
            MapEntryPoints => ".kuzushi/entry-points.json",
            BuildXRay => "x-ray/x-ray.md",
            BuildStrideThreatModel => ".kuzushi/threat-model.json",
            BuildPastaThreatModel => ".kuzushi/threat-model-pasta.json",
            BuildCodePropertyGraph => ".kuzushi/cpg.bin",
            BuildCodeQlDatabase => ".kuzushi/codeql-db",
            ThreatIntelCves => ".kuzushi/threat-intel/candidates.json",
            _ => return None,
        };
        Some(path)
    }

    /// Whether this task builds a reusable on-disk artifact whose presence is
    /// detected for reuse. Action tasks (scans, triage, patch) always run.
    pub fn produces_artifact(self) -> bool {
        self.artifact_relative_path().is_some()
    }

    /// External CLI prerequisite for this task. `Some(name)` means the
    /// task can only run when that binary is on PATH.
    pub fn required_cli(self) -> Option<&'static str> {
        use PlanningTaskId::*;
        match self {
            BuildCodePropertyGraph => Some("joern-parse"),
            BuildCodeQlDatabase | ScanCodeql => Some("codeql"),
            ScanSemgrep => Some("semgrep"),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_task_has_a_phase_and_tool() {
        for task in PlanningTaskId::ALL.iter().copied() {
            assert!(!task.tool_name().is_empty());
            assert!(!task.label().is_empty());
            let _ = task.phase();
        }
    }

    #[test]
    fn phases_partition_all_tasks() {
        let counted: usize = WorkflowPhase::ORDER
            .iter()
            .map(|phase| PlanningTaskId::in_phase(*phase).len())
            .sum();
        assert_eq!(counted, PlanningTaskId::ALL.len());
    }

    #[test]
    fn map_tasks_build_artifacts_actions_do_not() {
        assert!(PlanningTaskId::GatherRepoContext.produces_artifact());
        assert!(PlanningTaskId::BuildCodePropertyGraph.produces_artifact());
        assert!(!PlanningTaskId::ScanSemgrep.produces_artifact());
        assert!(!PlanningTaskId::TriageFindings.produces_artifact());
        assert!(!PlanningTaskId::ReverseEngineerBinary.produces_artifact());
    }

    #[test]
    fn codeql_scan_requires_the_codeql_cli() {
        assert_eq!(PlanningTaskId::ScanCodeql.required_cli(), Some("codeql"));
        assert_eq!(PlanningTaskId::ScanSemgrep.required_cli(), Some("semgrep"));
        assert_eq!(PlanningTaskId::TriageFindings.required_cli(), None);
    }
}
