//! In-process adapter over the cpg-rs engine (oxidized-joern).
//!
//! Owns the three seams kuzushi needs from a CPG engine:
//! - artifact conventions under `<target>/.kuzushi/cpg-rs/` (shape-versioned
//!   file names, so an engine upgrade self-invalidates stale graphs),
//! - implicit build-or-load of per-language [`cpg_incremental::Project`]s
//!   (seconds even on 1M-LOC targets — no operator prebuild step required),
//! - translation of kuzushi's literal catalog signals (`req.query`,
//!   `.execute(`) into a cpg-rs [`cpg_analysis::TaintSpec`] by harvesting
//!   matching call names from the built graph.
//!
//! Fidelity caveat, stated once for every consumer: cpg-rs taint is
//! name-based (summaries-first), not SSA/IFDS — recall-first, the
//! finding-review pass owns precision.

mod artifacts;
mod engine;
mod languages;
pub mod queries;
mod taint;

pub use artifacts::{artifact_dir, artifact_langs, artifact_path, has_artifacts};
pub use engine::{ensure_project, CpgBuildReport};
pub use languages::{canonical_language, detect_buildable_languages, supported_languages};
pub use taint::{
    harvest_regex_spec, harvest_spec, run_taint_query, CpgFlowQueryStats, HarvestedSpec,
    SignalSpec, MAX_FLOWS_PER_QUERY, MAX_HARVESTED_NAMES,
};

pub use cpg_analysis::{Finding, Step};
pub use cpg_cli::workspace::GRAPH_SHAPE_VERSION;
pub use cpg_incremental::Project;
