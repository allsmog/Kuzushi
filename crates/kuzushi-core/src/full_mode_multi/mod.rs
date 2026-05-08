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
mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod items_1;
mod items_2;
mod items_3;
mod items_5;
mod items_6;
mod run;
#[cfg(test)]
mod tests;

pub use items_1::ChunkPlan;
pub use items_1::FileBucket;
pub use items_1::FullModeConfig;
pub use items_1::FullModeLanguage;
pub use items_1::FullModePlan;
pub use items_1::FullModeReport;
pub use items_1::BYTES_PER_TOKEN;
pub use items_1::DEFAULT_DEPOSIT_USD_PER_CHUNK;
pub use items_1::DEFAULT_MAX_TOKENS_PER_CHUNK;
pub use items_1::MAX_FILE_BYTES;
pub use items_2::plan;
pub use items_5::cost_summary;
pub use items_6::report_to_tool_json;
pub use items_6::CostSummary;
pub use run::run;
