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
mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod items_1;
mod items_2;
mod items_4;
mod render_markdown;
#[cfg(test)]
mod tests;

pub use items_1::assemble_static_context;
pub use items_1::StaticContextSources;
pub use items_1::SUBGRAPH_LINE_WINDOW;
pub use items_1::SUBGRAPH_NODE_CAP;
