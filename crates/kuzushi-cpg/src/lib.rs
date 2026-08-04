//! In-process adapter over the cpg-rs engine (oxidized-joern).
//!
//! Owns the three seams kuzushi needs from a CPG engine:
//! - artifact conventions under `<target>/.kuzushi/cpg-rs/` (shape-versioned
//!   file names, so an engine upgrade self-invalidates stale graphs),
//! - implicit build-or-load of per-language projects,
//! - translation of kuzushi's literal catalog signals (`req.query`,
//!   `.execute(`) into an engine taint specification.
//!
//! The default build enables the private engine. The repository's public-core
//! validation contract first removes private Git resolution in a disposable
//! workspace, then builds with `--no-default-features`; that mode preserves the
//! public adapter types while every engine operation fails closed and artifact
//! readiness is false.

#[cfg(feature = "private-engine")]
mod artifacts;
#[cfg(not(feature = "private-engine"))]
mod disabled;
#[cfg(feature = "private-engine")]
mod engine;
#[cfg(feature = "private-engine")]
mod languages;
#[cfg(feature = "private-engine")]
pub mod queries;
#[cfg(feature = "private-engine")]
mod taint;

#[cfg(feature = "private-engine")]
pub use artifacts::{
    artifact_dir, artifact_langs, artifact_path, has_artifacts, scoped_artifact_path,
};
#[cfg(feature = "private-engine")]
pub use engine::{
    ensure_project, ensure_project_in, open_project_in, validate_graph_artifact, BuildLimits,
    BuildScope, CpgBuildReport, DEFAULT_MAX_SOURCE_FILES,
};
#[cfg(feature = "private-engine")]
pub use languages::{canonical_language, detect_buildable_languages, supported_languages};
#[cfg(feature = "private-engine")]
pub use taint::{
    harvest_regex_spec, harvest_spec, run_taint_query, CpgFlowQueryStats, HarvestedSpec,
    SignalSpec, MAX_FLOWS_PER_QUERY, MAX_HARVESTED_NAMES,
};

#[cfg(feature = "private-engine")]
pub use cpg_analysis::{Finding, Step};
#[cfg(feature = "private-engine")]
pub use cpg_cli::workspace::GRAPH_SHAPE_VERSION;
#[cfg(feature = "private-engine")]
pub use cpg_incremental::Project;

#[cfg(not(feature = "private-engine"))]
pub use disabled::*;

/// Whether this build contains the private in-process CPG implementation.
///
/// This is a compile-time fact, not a runtime probe. Consumers use it to keep
/// validation-only builds from advertising engine-backed capability.
pub const fn engine_available() -> bool {
    cfg!(feature = "private-engine")
}

/// Stable operator-facing explanation for a deliberately omitted engine.
pub const fn engine_unavailable_message() -> &'static str {
    "the private CPG engine is not compiled into this credential-free validation build; use the default `private-engine` feature and provide read access to allsmog/oxidized-joern"
}
