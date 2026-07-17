#[derive(Debug, Clone)]
pub(crate) struct SystemsHuntInput {
    pub(crate) max_findings: usize,
    pub(crate) max_surfaces: usize,
    pub(crate) max_trigger_hypotheses_per_surface: usize,
    pub(crate) max_cwe_classes: usize,
    pub(crate) artifact_dir: String,
    pub(crate) model: Option<String>,
    pub(crate) invariant_system_prompt: String,
    pub(crate) trigger_system_prompt: String,
    pub(crate) hunt_system_prompt: String,
    pub(crate) deep_semantic_cwe_system_prompt: String,
    pub(crate) deep_semantic_hunt_system_prompt: String,
    /// Max files visited by `collect_inventory`. Default 5000 (was 200):
    /// large enough to cover libxml2-class libraries in a single walk, tunable
    /// for million-LoC monorepos.
    pub(crate) max_files: usize,
    /// Bytes read per file during the fast classify pass. Default 16 KiB (was
    /// 4 KiB): captures roughly 250 lines without bloating wallclock.
    pub(crate) head_bytes: usize,
    /// Include docs/examples/tests in surface discovery. Defaults false so a
    /// root-target production hunt does not spend its surface budget on samples.
    pub(crate) include_non_production: bool,
}
