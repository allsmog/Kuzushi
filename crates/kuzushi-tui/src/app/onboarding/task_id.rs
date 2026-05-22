/// The eight foundational tasks an operator can select from the onboarding
/// planning picker. Each variant maps to a concrete tool (or a tool +
/// methodology option) and an artifact path used for prior-run detection.
///
/// Ordering of variants is the canonical UI order shown in the picker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PlanningTaskId {
    GatherRepoContext,
    MapEntryPoints,
    BuildXRay,
    BuildStrideThreatModel,
    BuildPastaThreatModel,
    BuildCodePropertyGraph,
    BuildCodeQlDatabase,
    ThreatIntelCves,
}

impl PlanningTaskId {
    pub const ALL: &'static [PlanningTaskId] = &[
        PlanningTaskId::GatherRepoContext,
        PlanningTaskId::MapEntryPoints,
        PlanningTaskId::BuildXRay,
        PlanningTaskId::BuildStrideThreatModel,
        PlanningTaskId::BuildPastaThreatModel,
        PlanningTaskId::BuildCodePropertyGraph,
        PlanningTaskId::BuildCodeQlDatabase,
        PlanningTaskId::ThreatIntelCves,
    ];

    pub fn label(self) -> &'static str {
        match self {
            PlanningTaskId::GatherRepoContext => "Gather repo context",
            PlanningTaskId::MapEntryPoints => "Map entry points",
            PlanningTaskId::BuildXRay => "Build X-ray",
            PlanningTaskId::BuildStrideThreatModel => "Build STRIDE threat model",
            PlanningTaskId::BuildPastaThreatModel => "Build PASTA threat model",
            PlanningTaskId::BuildCodePropertyGraph => "Build code property graph",
            PlanningTaskId::BuildCodeQlDatabase => "Build CodeQL DB",
            PlanningTaskId::ThreatIntelCves => "Threat intel (CVEs)",
        }
    }

    /// Tool name dispatched when this task runs. STRIDE and PASTA share
    /// `threat-model:build` and differ only in their `methodology` input.
    pub fn tool_name(self) -> &'static str {
        match self {
            PlanningTaskId::GatherRepoContext => "context:build",
            PlanningTaskId::MapEntryPoints => "entry-points:extract",
            PlanningTaskId::BuildXRay => "x-ray:run",
            PlanningTaskId::BuildStrideThreatModel | PlanningTaskId::BuildPastaThreatModel => {
                "threat-model:build"
            }
            PlanningTaskId::BuildCodePropertyGraph => "cpg:build",
            PlanningTaskId::BuildCodeQlDatabase => "codeql:create-db",
            PlanningTaskId::ThreatIntelCves => "threat-intel:discover",
        }
    }

    /// Whether the task requires an agent runtime. Used to surface a
    /// "model-backed" / "no model cost" hint next to each row.
    pub fn is_model_backed(self) -> bool {
        matches!(
            self,
            PlanningTaskId::BuildXRay
                | PlanningTaskId::BuildStrideThreatModel
                | PlanningTaskId::BuildPastaThreatModel
        )
    }

    /// Relative artifact path under the workspace root used to determine
    /// whether the task has already been run.
    pub fn artifact_relative_path(self) -> &'static str {
        match self {
            PlanningTaskId::GatherRepoContext => ".kuzushi/context-snapshot.json",
            PlanningTaskId::MapEntryPoints => ".kuzushi/entry-points.json",
            PlanningTaskId::BuildXRay => "x-ray/x-ray.md",
            PlanningTaskId::BuildStrideThreatModel => ".kuzushi/threat-model.json",
            PlanningTaskId::BuildPastaThreatModel => ".kuzushi/threat-model-pasta.json",
            PlanningTaskId::BuildCodePropertyGraph => ".kuzushi/cpg.bin",
            PlanningTaskId::BuildCodeQlDatabase => ".kuzushi/codeql-db",
            PlanningTaskId::ThreatIntelCves => ".kuzushi/threat-intel/candidates.json",
        }
    }

    /// External CLI prerequisite for this task. `Some(name)` means the
    /// task can only run when that binary is on PATH.
    pub fn required_cli(self) -> Option<&'static str> {
        match self {
            PlanningTaskId::BuildCodePropertyGraph => Some("joern-parse"),
            PlanningTaskId::BuildCodeQlDatabase => Some("codeql"),
            _ => None,
        }
    }
}
