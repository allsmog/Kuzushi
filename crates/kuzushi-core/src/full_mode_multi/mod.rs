/// Default chunk budget in approximate tokens. Sized so a chunk fits in
/// a single 200k-context call with room for the system prompt + output.

/// Approximate bytes-per-token. Empirically ~3.6 across mixed C/Rust
/// code. Used for chunk packing without invoking a real tokenizer.

/// Hard cap on per-file size before we split. Beyond this we break on
/// top-level brace boundaries.

/// Directories the walker never descends into. Mirrors
/// `systems_hunt::SKIP_DIRS`.

/// Conservative initial deposit per chunk. Real cost surfaces from the
/// bridge response and settles via SpendLimiter::refund.

/// Plan only — produces the chunk layout without any LLM calls. Use this
/// for `--dry-run-cost-estimate` and unit tests.

/// Run the full pass — dispatches each chunk through the routed runtime.

/// Cost-estimate summary for `--dry-run-cost-estimate`. Prices are
/// rough — a real estimate would use per-model token pricing tables;
/// for v1 we report bands.

/// Map a [`FullModeReport`] to a JSON Value suitable for tool output.
use crate::agent_router::{AgentRole, RoutedRuntime};
use crate::findings::{Finding, Severity};
use crate::runtime::AgentQueryRequest;
use crate::spend::{Operation, SpendLimiter, SpendTicket};
use crate::structured_output::{query_required_structured_json, StructuredJsonContract};
use anyhow::{Context, Result};
pub(crate) use full_mode_model::*;
pub(crate) use plan::*;
pub(crate) use render_chunk_prompt::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
pub(crate) use walk_files::*;
mod full_mode_model;
mod plan;
mod render_chunk_prompt;
mod report_to_tool_json;
mod run;
#[cfg(test)]
mod tests;
mod walk_files;

pub use full_mode_model::ChunkPlan;
pub use full_mode_model::FileBucket;
pub use full_mode_model::FullModeConfig;
pub use full_mode_model::FullModeLanguage;
pub use full_mode_model::FullModePlan;
pub use full_mode_model::FullModeReport;
pub use full_mode_model::BYTES_PER_TOKEN;
pub use full_mode_model::DEFAULT_DEPOSIT_USD_PER_CHUNK;
pub use full_mode_model::DEFAULT_MAX_TOKENS_PER_CHUNK;
pub use full_mode_model::MAX_FILE_BYTES;
pub use plan::plan;
pub use render_chunk_prompt::cost_summary;
pub use report_to_tool_json::report_to_tool_json;
pub use report_to_tool_json::CostSummary;
pub use run::run;
