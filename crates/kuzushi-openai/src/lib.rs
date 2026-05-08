/// Translate the loop driver's [`LoopHistoryEntry`] sequence into Anthropic's
/// Messages API shape. The first message is always the user's initial
/// prompt; subsequent messages alternate assistant/user as the loop ran.
pub mod anthropic_oauth;
pub mod oauth;

mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod items_1;
mod items_2;
mod items_3;
mod items_4;
mod query_blocking;
#[cfg(test)]
mod tests;

pub use anthropic_oauth::{AnthropicOAuthRuntime, AnthropicOAuthRuntimeOptions};
pub use items_1::PiAgentCoreRuntime;
pub use oauth::{probe as probe_anthropic_oauth, OauthReadiness};
