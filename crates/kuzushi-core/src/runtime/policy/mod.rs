mod no_silent_fallback;

pub use no_silent_fallback::{
    bridge_api_key_env_for_model, canonical_model_spec, require_configured_model,
    resolve_explicit_model, validate_model_api_key_env, validate_model_spec,
};
