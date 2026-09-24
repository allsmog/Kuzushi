//! v3 durable identity primitives.
//!
//! These helpers are intentionally independent of SQLite and scanner runtime
//! state. They produce content-addressed identifiers that can be reused by the
//! event log, projection tables, and TUI review frames.

pub mod finding_identity;
pub mod hash;

pub use finding_identity::{
    compute_observation_hash_v3, compute_stable_fp_v3, discriminated_fingerprint_for_tool,
    stable_fingerprint_for_tool,
    ObservationHashInput, StableFindingInput,
};
pub use hash::{hash_parts, Blake3Hash};
