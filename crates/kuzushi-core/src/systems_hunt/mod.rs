/// Walk `target` with the (configurable) systems-hunt surface
/// scorer and return the ranked surface list — *without* the LLM
/// invariant/trigger/finding stages. Useful for plugging the surface
/// ranker into custom pipelines, scoring scripts, and the
/// libxml2-style live experiments.
///
/// `input` accepts the same JSON shape as
/// `run_systems_hunt_report` (`maxFiles`, `headBytes`,
/// `maxSurfaces`, ...). Index augmentation runs internally; failures
/// are silent.

/// Pick a sub-agent role for the invariant-extraction step based on the
/// surface mix in `context`. The first matching rule wins:
/// - Any Rust unsafe-region surface → UnsafeBlockReasoner
/// - Any FFI-boundary surface → FfiBoundaryReasoner
/// - Any resource-provenance surface in `.rs` → LifetimeAliasingReasoner
/// - Otherwise → Generic (no preamble change)

/// Augment surfaces with structural data from the code-index facade
/// when one is available. When no index backend is live (joern absent),
/// returns the surfaces unchanged. Fails soft on any backend error.
///
/// Use this from agentic flows that want signal beyond the
/// text-walking `gather_systems_context` produces. The legacy DAG
/// pipeline does not call this function — opt-in only.

/// Score-aware augmentation: contributes deterministic bumps to each
/// surface's `score` based on what the codeindex facade can prove
/// about it. Now called from the main `gather_systems_context` flow
/// (was opt-in via `try_augment_with_index`).
///
/// Bumps:
/// - Rust unsafe-region surface with N indexed unsafe blocks in the
///   same file: `+10 × min(N, 5)`.
/// - FFI-boundary surface with at least one indexed FFI hit: `+8`.
/// - Surface where joern's taint engine finds an attacker→sink path:
///   `+15` and prepends a "codeindex: taint reachable" reason.
///
/// All bumps are best-effort. When no joern backend is live, the
/// surfaces pass through unchanged.
mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod items_1;
mod items_10;
mod items_11;
mod items_12;
mod items_14;
mod items_15;
mod items_16;
mod items_17;
mod items_18;
mod items_19;
mod items_2;
mod items_20;
mod items_21;
mod items_22;
mod items_3;
mod items_4;
mod items_5;
mod items_6;
mod items_7;
mod items_8;
mod items_9;
mod normalize_systems_hunt_findings;
#[cfg(test)]
mod tests;

pub use items_1::SystemsContextOutput;
pub(crate) use items_10::pick_role_for_invariants;
pub(crate) use items_10::score_with_index;
pub use items_10::try_augment_with_index;
pub use items_2::RankedSystemsSurface;
pub use items_2::SystemsCodeLocation;
pub use items_2::SystemsContextMetadata;
pub use items_2::SystemsHelperTemplate;
pub use items_2::SystemsInvariant;
pub use items_2::SystemsInvariantOutput;
pub use items_2::SystemsSurfacePack;
pub use items_2::SystemsSurfaceSignal;
pub use items_2::SystemsTriggerHypothesis;
pub use items_2::SystemsTriggerOutput;
pub use items_3::execute_systems_hunt_tool;
pub use items_3::DeepSemanticCweOutput;
pub use items_3::DeepSemanticCweSelection;
pub use items_3::SystemsHuntPersistedRun;
pub use items_3::SystemsHuntReport;
pub use items_4::gather_surfaces;
pub use items_5::run_systems_hunt_report;
