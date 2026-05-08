use super::*;

pub(crate) const SYSTEMS_INVARIANT_SYSTEM_PROMPT: &str = "Systems Hunt invariant extractor";

pub(crate) const SYSTEMS_TRIGGER_SYSTEM_PROMPT: &str = "Systems Hunt trigger synthesizer";

pub(crate) const SYSTEMS_HUNT_SYSTEM_PROMPT: &str = "Systems Hunt low-level vulnerability hunter";

pub(crate) const DEEP_SEMANTIC_CWE_SYSTEM_PROMPT: &str = "Deep Semantic CWE selector";

pub(crate) const DEEP_SEMANTIC_HUNT_SYSTEM_PROMPT: &str = "Deep Semantic Hunt vulnerability hunter";

pub(crate) const SYSTEMS_EXTENSIONS: &[&str] = &[
    "c", "cc", "cpp", "cxx", "h", "hh", "hpp", "hxx", "rs", "go", "zig",
];

pub(crate) const SKIP_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".kuzushi",
    ".next",
    ".turbo",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "vendor",
];

#[derive(Debug, Clone)]
pub(crate) struct SystemsHuntInput {
    pub(crate) max_findings: usize,
    pub(crate) max_surfaces: usize,
    pub(crate) max_trigger_hypotheses_per_surface: usize,
    pub(crate) max_cwe_classes: usize,
    pub(crate) artifact_dir: String,
    pub(crate) model: Option<String>,
    /// Max files visited by `collect_inventory`. Default 5000 (was
    /// 200) — large enough to cover libxml2-class libraries in a
    /// single walk; tunable for million-LoC monorepos.
    pub(crate) max_files: usize,
    /// Bytes read per file during the *fast* classify pass. Default
    /// 16 KiB (was 4 KiB) — captures ~250 lines of code, enough for
    /// most function-level signals without bloating wallclock.
    pub(crate) head_bytes: usize,
}

impl SystemsHuntInput {
    pub(crate) fn from_tool_input(input: &Value) -> Result<Self> {
        Ok(Self {
            max_findings: positive_usize(input, &["maxFindings", "max_findings"], 30)?,
            max_surfaces: positive_usize(input, &["maxSurfaces", "max_surfaces"], 50)?,
            max_files: positive_usize(input, &["maxFiles", "max_files"], 5000)?,
            head_bytes: positive_usize(input, &["headBytes", "head_bytes"], 16384)?,
            max_trigger_hypotheses_per_surface: positive_usize(
                input,
                &[
                    "maxTriggerHypothesesPerSurface",
                    "max_trigger_hypotheses_per_surface",
                ],
                3,
            )?,
            max_cwe_classes: positive_usize(input, &["maxCweClasses", "max_cwe_classes"], 6)?,
            artifact_dir: optional_nonempty_string(input, "artifactDir")?
                .or(optional_nonempty_string(input, "artifact_dir")?)
                .unwrap_or_else(|| ".kuzushi/systems-hunt".to_string()),
            model: optional_nonempty_string(input, "model")?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SystemsContextOutput {
    pub surfaces: Vec<RankedSystemsSurface>,
    pub surface_packs: Vec<SystemsSurfacePack>,
    pub metadata: SystemsContextMetadata,
}
