mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod items_1;
mod items_2;
mod items_3;
mod items_4;
/// Construction options for [`AnthropicOAuthRuntime`].

/// Per-model rate table (USD per token). Numbers are approximate
/// public prices and are recomputed against the response's
/// `usage.input_tokens` / `usage.output_tokens` per call. Operators
/// who want exact billing should rely on Anthropic's invoiced totals;
/// this is only used to drive in-process cost caps.

/// Resolve a tier handle to a concrete Anthropic model name. Operators
/// that want a different mapping (e.g. pin Cheap to a specific Haiku
/// minor version) override via the `configured` argument.

#[cfg(test)]
mod tests;

pub use items_1::AnthropicOAuthRuntime;
pub use items_1::AnthropicOAuthRuntimeOptions;
