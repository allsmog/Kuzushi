//! Kuzushi context boundary.
//!
//! Repository context is deterministic input for scanners, threat modeling,
//! recommender planning, and reports. It should remain free of LLM dispatch and
//! UI rendering concerns.

pub use crate::repository_inventory::*;
pub use crate::static_context::*;
