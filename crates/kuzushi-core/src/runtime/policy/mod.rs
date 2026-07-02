mod no_silent_fallback;

pub use no_silent_fallback::{
    canonical_model_spec, require_configured_model, resolve_explicit_model, validate_model_spec,
    validate_model_api_key_env,
};
