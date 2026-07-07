mod environment;
mod readiness;

#[cfg(test)]
mod tests;

pub use environment::has_env_token;
pub use readiness::{
    native_anthropic_access_token, probe, probe_path, resolve_credentials_path, OauthReadiness,
    DEFAULT_CREDENTIALS_REL_PATH,
};

#[cfg(test)]
pub(crate) use environment::current_unix_ms;
