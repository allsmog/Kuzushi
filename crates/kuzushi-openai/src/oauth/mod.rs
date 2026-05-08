mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod items_1;
mod items_2;
/// Default credentials path under the user's home directory.

/// What we found when probing the OAuth state. No token bytes leak into here.

/// Probe an Anthropic OAuth credentials file. Returns a structured readiness
/// status; the caller decides whether to warn, error, or proceed based on it.
///
/// This function does NOT refresh, does NOT call out to the bridge, and does
/// NOT log token bytes.

/// Same as [`probe`] but takes an explicit path. Useful for tests.

/// Resolve the credentials path, defaulting to `$HOME/.kuzushi/oauth-credentials.json`.

/// Whether an env-var fallback token is set. The bridge's auth chain prefers
/// OAuth, so if both are present the OAuth file wins.

#[cfg(test)]
mod tests;

pub use items_1::probe;
pub use items_1::probe_path;
pub use items_1::resolve_credentials_path;
pub use items_1::OauthReadiness;
pub use items_1::DEFAULT_CREDENTIALS_REL_PATH;
pub use items_2::has_env_token;
