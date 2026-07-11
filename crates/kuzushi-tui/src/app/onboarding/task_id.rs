use kuzushi_core::WorkflowPhase;

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
    /// Retained only to decode older saved plans; no longer offered by the
    /// source-security phase picker.
    #[allow(dead_code)]
    ReverseEngineerBinary,
    // 崩 KUZUSHI · hunt — find vulnerabilities.
    ScanSecrets,
    ScanSemgrep,
    ScanCodeql,
    ScanAgenticSast,
    HuntTaint,
    HuntThreatModel,
    HuntSystems,
    /// Retained only to decode older saved plans; superseded by the supported
    /// systems/dataflow engines and no longer offered by Planning.
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
        PlanningTaskId::ScanSecrets,
        PlanningTaskId::ScanSemgrep,
        PlanningTaskId::ScanCodeql,
        PlanningTaskId::ScanAgenticSast,
        PlanningTaskId::HuntTaint,
        PlanningTaskId::HuntThreatModel,
        PlanningTaskId::HuntSystems,
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
            VerifyFindings => "Verify findings",
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
            HuntThreatModel => "offense-review:threat-hunt",
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
        assert!(PlanningTaskId::GatherRepoContext
            .artifact_relative_path()
            .is_some());
        assert!(PlanningTaskId::BuildCodePropertyGraph
            .artifact_relative_path()
            .is_some());
        assert!(PlanningTaskId::ScanSemgrep
            .artifact_relative_path()
            .is_none());
        assert!(PlanningTaskId::TriageFindings
            .artifact_relative_path()
            .is_none());
        assert!(PlanningTaskId::ReverseEngineerBinary
            .artifact_relative_path()
            .is_none());
    }

    #[test]
    fn codeql_scan_requires_the_codeql_cli() {
        assert_eq!(PlanningTaskId::ScanCodeql.required_cli(), Some("codeql"));
        assert_eq!(PlanningTaskId::ScanSemgrep.required_cli(), Some("semgrep"));
        assert_eq!(PlanningTaskId::TriageFindings.required_cli(), None);
    }

    /// Drift guard: the curated planning-task phase must agree with the
    /// canonical `ToolPhase` stamped on each task's registry tool. This proves
    /// the descriptor phase field and the walker's task list are one truth.
    #[test]
    fn planning_task_phase_agrees_with_descriptor_phase() {
        use kuzushi_core::modules::ToolPhase;
        use kuzushi_core::V2Config;

        let app = crate::ShellApp::new(V2Config::default(), None);
        let registry = app.registry();

        for task in PlanningTaskId::ALL.iter().copied() {
            if task.is_inline_action() {
                continue; // inline actions (e.g. attach) are not registry tools
            }
            let Some(descriptor) = registry.resolve_tool(task.tool_name()) else {
                continue; // tool not registered in this build (optional adapters)
            };
            let expected = match task.phase() {
                WorkflowPhase::Map => ToolPhase::Map,
                WorkflowPhase::Hunt => ToolPhase::Hunt,
                WorkflowPhase::Confirm => ToolPhase::Confirm,
                WorkflowPhase::Fix => ToolPhase::Fix,
            };
            assert_eq!(
                descriptor.phase,
                expected,
                "phase drift for task {:?} (tool {})",
                task,
                task.tool_name()
            );
        }
    }

    /// Drift guard: this onboarding walker has its own
    /// `PlanningTaskId::phase()` table, and `kuzushi_core`'s autonomy gate has
    /// its own independent `tool_phase()` table (`modules::autonomy::tool_phase`,
    /// keyed by dispatched tool name rather than task id). Both exist to
    /// answer the same question — "which spine phase does this action belong
    /// to?" — so a tool whose two answers disagree would let the walker
    /// present a task as (say) Map-phase while the shared gate refuses it
    /// under a Map-ceiling posture (or vice versa). `AttachFiles` is the one
    /// task that never dispatches a tool (`is_inline_action() == true`), so
    /// there is nothing for the gate to classify; every other task's
    /// dispatched tool name must classify to exactly the phase the walker
    /// already assigns it.
    #[test]
    fn task_phase_matches_the_core_autonomy_tool_phase_table() {
        for task in PlanningTaskId::ALL.iter().copied() {
            if task.is_inline_action() {
                continue;
            }
            let tool_name = task.tool_name();
            assert_eq!(
                kuzushi_core::tool_phase(tool_name),
                Some(task.phase()),
                "{task:?} (tool {tool_name:?}) claims phase {:?} in \
                 PlanningTaskId::phase() but kuzushi_core::tool_phase() \
                 disagrees — the two tool→phase tables have drifted",
                task.phase()
            );
        }
    }
}
