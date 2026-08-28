mod model_auth_binding;
mod no_silent_fallback;
mod tie_break_escalation;

pub use model_auth_binding::{
    bind_model_auth, public_auth_provider, require_model_auth_binding, ModelAuthBinding,
    PublicAuthProvider,
};
pub use no_silent_fallback::{
    bridge_api_key_env_for_model, canonical_model_spec, require_configured_model,
    resolve_explicit_model, validate_model_api_key_env, validate_model_spec,
};
pub use tie_break_escalation::{decide_tie_break, TieBreakEscalation, TieBreakRefusal};
