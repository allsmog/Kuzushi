/// Window (in lines) around the finding's `start_line` we keep when
/// slicing the evidence subgraph. Enough to cover a short function;
/// tight enough that a 200-node finding doesn't blow the prompt.

/// Cap on evidence nodes kept in the slice. Prevents prompts from
/// ballooning when a finding lights up a hot region of the graph.

/// Inputs the assembler needs that aren't on `Finding` directly.

/// Assemble the pre-populated static-evidence block, or `None` when
/// the finding has no known signals (no registry hits, no narrative
/// content, no graph nodes).

/// Infer language from extension. Mirrors `code_nav::symbol_index::detect_language`
/// but kept local to avoid a public-API coupling.
use crate::findings::{Finding, StaticProofState};
use crate::static_evidence::{
    StaticEvidenceEdge, StaticEvidenceNode, StaticEvidenceNodeKind, StaticEvidenceStore,
};
use crate::static_narrative::{build_static_narrative_report, StaticFindingNarrative};
use crate::static_ranking::{rank_static_findings, StaticRankedFinding};
use crate::static_registry::{
    match_static_registry, StaticRegistryKind, StaticRegistryMatch, StaticRegistryQuery,
};
pub(crate) use group_registry_by_kind::*;
pub(crate) use match_registry_for::*;
pub(crate) use render_markdown::*;
use std::path::Path;
mod assemble_static_context;
mod group_registry_by_kind;
mod match_registry_for;
mod render_markdown;
#[cfg(test)]
mod tests;

pub use assemble_static_context::assemble_static_context;
pub use assemble_static_context::StaticContextSources;
pub use assemble_static_context::SUBGRAPH_LINE_WINDOW;
pub use assemble_static_context::SUBGRAPH_NODE_CAP;
