/// Declarative hint that the operator expects Anthropic OAuth as the
/// credential source for `anthropic:*` models.
///
/// The bridge (`scripts/pi-agent-core-bridge.mjs`) is the actual refresh
/// authority — it loads `oauth-credentials.json`, refreshes via
/// `@mariozechner/pi-ai/oauth`, and forwards the access token. This Rust
/// struct exists so:
///
/// * `validate_config` can fail fast at startup if the operator declared
///   OAuth but the credentials file is missing or unreadable, instead of
///   waiting for the first LLM call.
/// * The TUI / CLI can describe the configured auth source without
///   round-tripping the bridge.
///
/// **No secret data is ever stored in this struct.** It only carries a
/// path and toggle flags. Tokens live in the file and the bridge process.
mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod items_1;
mod items_2;
mod items_3;
#[cfg(test)]
mod tests;

pub use items_1::AnthropicOauthConfig;
pub use items_1::ConfigPaths;
pub use items_1::RuntimeConfig;
pub use items_1::RuntimeKind;
pub use items_1::V2Config;
pub use items_2::load_anthropic_oauth_config;
pub use items_2::load_config;
pub use items_2::load_config_for_target;
pub use items_2::write_default_config;
