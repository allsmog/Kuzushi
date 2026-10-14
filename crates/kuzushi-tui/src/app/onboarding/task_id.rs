use kuzushi_core::WorkflowPhase;
use std::path::{Path, PathBuf};

/// Every task an operator can select across the five engagement phases. Each
/// variant maps to a concrete tool (or a tool + option) and, for the Map-phase
/// tasks that build reusable artifacts, an artifact path used for prior-run
/// detection. Scan/Review/Prove/Fix tasks are actions (no cached artifact).
///
/// Ordering of variants is the canonical UI/run order, grouped by phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PlanningTaskId {
    // 組 KUMI-KATA · map — context & analysis artifacts.
    AttachFiles,
    GatherRepoContext,
    MapEntryPoints,
    /// Big-monorepo first move: materialize the module decomposition
    /// (`.kuzushi/project-model/scopes.json`) before whole-repo modeling.
    DecomposeModules,
    BuildXRay,
    /// One threat model per target; methodology and seed mode are options on
    /// the shared `threat-model:build` tool, not separate planner rows.
    BuildThreatModel,
    /// Import a supplied context document as an inactive revision for Map review.
    ImportThreatModel,
    /// Retained only to decode older saved plans; superseded by the merged
    /// `BuildThreatModel` row.
    #[allow(dead_code)]
    BuildStrideThreatModel,
    /// Retained only to decode older saved plans; superseded by the merged
    /// `BuildThreatModel` row.
    #[allow(dead_code)]
    BuildPastaThreatModel,
    BuildCodePropertyGraph,
    BuildCodeQlDatabase,
    ThreatIntelCves,
    /// Author fuzz harnesses for agentic-fuzz-engine workorders (builds the
    /// instrument, hence Map — like the CodeQL DB).
    MapFuzzAuthor,
    /// Retained only to decode older saved plans; no longer offered by the
    /// source-security phase picker.
    #[allow(dead_code)]
    ReverseEngineerBinary,
    // Scan — find candidate vulnerabilities and security signals.
    ScanSecrets,
    ScanSemgrep,
    ScanCodeql,
    ScanAgenticSast,
    HuntTaint,
    HuntThreatModel,
    HuntSystems,
    /// Run bounded agentic-fuzz-engine campaign rounds and import verified
    /// crashes (C/C++ targets).
    ScanFuzz,
    /// Replay every built engine target's corpus under an MSan-variant fuzzer
    /// (uninitialized-read oracle the ASAN lane cannot fire).
    ScanFuzzSweep,
    /// Replay every built engine target's corpus through auto-resolved fork
    /// vs upstream implementations (silent-wrong-data oracle).
    ScanFuzzDifferential,
    /// Retained only to decode older saved plans; superseded by the supported
    /// systems/dataflow engines and no longer offered by Planning.
    HuntUseAfterFree,
    // Review — triage and decide candidate findings.
    TriageFindings,
    /// Model-driven corpus dedupe: collapse cross-run/cross-tool
    /// rediscoveries of one defect onto a canonical finding.
    DedupeFindings,
    /// Compose confirmed findings into multi-step attack chains.
    HuntChains,
    // Prove — verify actionable findings with empirical evidence.
    VerifyFindings,
    // 掛 KAKE · fix — patch & report.
    PatchFindings,
    /// Retained for saved plan compatibility. New exports use the Report surface.
    #[allow(dead_code)]
    BuildReport,
}

impl PlanningTaskId {
    pub const ALL: &'static [PlanningTaskId] = &[
        PlanningTaskId::AttachFiles,
        PlanningTaskId::GatherRepoContext,
        PlanningTaskId::MapEntryPoints,
        PlanningTaskId::DecomposeModules,
        PlanningTaskId::BuildXRay,
        PlanningTaskId::BuildThreatModel,
        PlanningTaskId::ImportThreatModel,
        PlanningTaskId::BuildCodePropertyGraph,
        PlanningTaskId::BuildCodeQlDatabase,
        PlanningTaskId::ThreatIntelCves,
        PlanningTaskId::MapFuzzAuthor,
        PlanningTaskId::ScanSecrets,
        PlanningTaskId::ScanSemgrep,
        PlanningTaskId::ScanCodeql,
        PlanningTaskId::ScanAgenticSast,
        PlanningTaskId::HuntTaint,
        PlanningTaskId::HuntThreatModel,
        PlanningTaskId::HuntSystems,
        PlanningTaskId::ScanFuzz,
        PlanningTaskId::ScanFuzzSweep,
        PlanningTaskId::ScanFuzzDifferential,
        PlanningTaskId::TriageFindings,
        PlanningTaskId::DedupeFindings,
        PlanningTaskId::HuntChains,
        PlanningTaskId::VerifyFindings,
        PlanningTaskId::PatchFindings,
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
            | DecomposeModules
            | BuildXRay
            | BuildThreatModel
            | ImportThreatModel
            | BuildStrideThreatModel
            | BuildPastaThreatModel
            | BuildCodePropertyGraph
            | BuildCodeQlDatabase
            | ThreatIntelCves
            | MapFuzzAuthor
            | ReverseEngineerBinary => WorkflowPhase::Map,
            ScanSecrets | ScanSemgrep | ScanCodeql | ScanAgenticSast | HuntTaint
            | HuntThreatModel | HuntSystems | ScanFuzz | ScanFuzzSweep | ScanFuzzDifferential
            | HuntUseAfterFree => WorkflowPhase::Scan,
            TriageFindings | DedupeFindings | HuntChains => WorkflowPhase::Review,
            VerifyFindings => WorkflowPhase::Prove,
            PatchFindings | BuildReport => WorkflowPhase::Fix,
        }
    }

    pub fn label(self) -> &'static str {
        use PlanningTaskId::*;
        match self {
            AttachFiles => "Attach reference files",
            GatherRepoContext => "Gather repo context",
            MapEntryPoints => "Map entry points",
            DecomposeModules => "Decompose into modules",
            BuildXRay => "Build X-ray",
            BuildThreatModel => "Build threat model",
            ImportThreatModel => "Import context document",
            BuildStrideThreatModel => "Build STRIDE threat model",
            BuildPastaThreatModel => "Build PASTA threat model",
            BuildCodePropertyGraph => "Build code property graph",
            BuildCodeQlDatabase => "Build CodeQL DB",
            ThreatIntelCves => "Inventory deps for CVE harvest",
            MapFuzzAuthor => "Author fuzz harnesses (AFE)",
            ReverseEngineerBinary => "Reverse-engineer binary",
            ScanSecrets => "Scan for secrets",
            ScanSemgrep => "Semgrep SAST scan",
            ScanCodeql => "CodeQL security scan",
            ScanAgenticSast => "Agentic SAST review",
            HuntTaint => "Taint dataflow hunt",
            HuntThreatModel => "Threat-model-driven hunt",
            HuntSystems => "Systems-level semantic hunt",
            ScanFuzz => "Coverage fuzzing (AFE)",
            ScanFuzzSweep => "MSan corpus sweep (AFE)",
            ScanFuzzDifferential => "Differential replay (AFE)",
            HuntUseAfterFree => "Use-after-free hunt (C/C++)",
            TriageFindings => "Triage findings",
            DedupeFindings => "Dedupe findings corpus",
            HuntChains => "Hunt attack chains",
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
            DecomposeModules => "pack:suggest-shards",
            BuildXRay => "x-ray:run",
            BuildThreatModel | BuildStrideThreatModel | BuildPastaThreatModel => {
                "threat-model:build"
            }
            ImportThreatModel => "threat-model:import",
            BuildCodePropertyGraph => "cpg:build",
            BuildCodeQlDatabase => "codeql:create-db",
            ThreatIntelCves => "threat-intel:discover",
            MapFuzzAuthor => "fuzz:author",
            ReverseEngineerBinary => "pwn:reverse",
            ScanSecrets => "secret-scan:scan",
            ScanSemgrep => "semgrep:scan",
            ScanCodeql => "codeql:scan",
            ScanAgenticSast => "agentic-sast:scan",
            HuntTaint => "taint-iris-next:hunt",
            HuntThreatModel => "offense-review:threat-hunt",
            HuntSystems => "systems-hunt:systems-hunt",
            ScanFuzz => "fuzz:run",
            ScanFuzzSweep => "fuzz:sweep",
            ScanFuzzDifferential => "fuzz:differential",
            HuntUseAfterFree => "uaf-hunt:hunt",
            TriageFindings => "triage:run",
            DedupeFindings => "triage:dedupe",
            HuntChains => "triage:chain-hunt",
            VerifyFindings => "verify:finding",
            PatchFindings => "patch:finding",
            BuildReport => "report:build",
        }
    }

    /// Stable Activity identity for one planned capability invocation.
    /// The merged threat-model row uses the plain tool name; the legacy
    /// decorated ids remain only so older saved plans replay unchanged.
    pub(crate) fn activity_task_id(self) -> String {
        match self {
            Self::BuildStrideThreatModel => "threat-model:build[stride]".to_string(),
            Self::BuildPastaThreatModel => "threat-model:build[pasta]".to_string(),
            _ => self.tool_name().to_string(),
        }
    }

    /// Whether the task requires an agent runtime. Used to surface a
    /// "model-backed" / "no model cost" hint next to each row.
    pub fn is_model_backed(self) -> bool {
        use PlanningTaskId::*;
        matches!(
            self,
            BuildXRay
                | BuildThreatModel
                | BuildStrideThreatModel
                | BuildPastaThreatModel
                | MapFuzzAuthor
                | ScanAgenticSast
                | HuntTaint
                | HuntThreatModel
                | HuntSystems
                | HuntUseAfterFree
                | TriageFindings
                | DedupeFindings
                | HuntChains
                | VerifyFindings
                | PatchFindings
        )
    }

    pub fn is_inline_action(self) -> bool {
        matches!(self, PlanningTaskId::AttachFiles)
    }

    /// Relative artifact path under the workspace root used to determine
    /// whether the task has already been run. `None` for action tasks
    /// (Scan/Review/Prove/Fix and reverse-engineering) that don't cache a
    /// reusable artifact at a fixed path.
    pub fn artifact_relative_path(self) -> Option<&'static str> {
        use PlanningTaskId::*;
        let path = match self {
            GatherRepoContext => ".kuzushi/context-snapshot.json",
            MapEntryPoints => ".kuzushi/entry-points.json",
            BuildXRay => "x-ray/x-ray.md",
            // One live model regardless of methodology; the legacy PASTA row
            // probes the same file (nothing ever wrote the old phantom
            // `.kuzushi/threat-model-pasta.json`).
            BuildThreatModel | BuildStrideThreatModel | BuildPastaThreatModel => {
                ".kuzushi/threat-model.json"
            }
            DecomposeModules => ".kuzushi/v3/project-model/scopes.json",
            // cpg-rs writes shape-versioned graphs under this directory; the
            // pre-cutover `.kuzushi/cpg.bin` joern path was never written, so
            // the row showed Missing forever even after a successful build.
            BuildCodePropertyGraph => ".kuzushi/cpg-rs",
            BuildCodeQlDatabase => ".kuzushi/v3/codeql-db",
            ThreatIntelCves => ".kuzushi/threat-intel/candidates.json",
            _ => return None,
        };
        Some(path)
    }

    pub fn artifact_path(self, target: &Path) -> Option<PathBuf> {
        if self == Self::DecomposeModules {
            return Some(kuzushi_core::workspace::project_model_scopes_path(target));
        }
        if self == Self::BuildCodePropertyGraph {
            return Some(kuzushi_core::cpg_artifact_dir(target));
        }
        self.artifact_relative_path().map(|path| target.join(path))
    }

    /// External CLI prerequisite for this task. `Some(name)` means the
    /// task can only run when that binary is on PATH.
    pub fn required_cli(self) -> Option<&'static str> {
        use PlanningTaskId::*;
        match self {
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
    fn map_plan_offers_runtime_free_context_import_as_an_explicit_action() {
        let task = PlanningTaskId::in_phase(WorkflowPhase::Map)
            .into_iter()
            .find(|task| task.tool_name() == "threat-model:import")
            .expect("Map needs a visible context import choice");
        assert!(!task.is_model_backed());
        assert!(
            task.artifact_relative_path().is_none(),
            "inactive imports cannot reuse the active mirror"
        );
    }

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
    fn decomposition_uses_the_canonical_v3_scope_tree_path() {
        let target = Path::new("/target");
        assert_eq!(
            PlanningTaskId::DecomposeModules.artifact_path(target),
            Some(kuzushi_core::workspace::project_model_scopes_path(target))
        );
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
                WorkflowPhase::Scan => ToolPhase::Scan,
                WorkflowPhase::Review => ToolPhase::Review,
                WorkflowPhase::Prove => ToolPhase::Prove,
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
