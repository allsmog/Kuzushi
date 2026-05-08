use crate::findings::StaticProofState;
pub(crate) use default_static_registry::*;
use serde::Serialize;
mod default_static_registry;
mod match_static_registry;
mod registry_model;
#[cfg(test)]
mod tests;

pub use match_static_registry::match_static_registry;
pub use registry_model::default_static_registry;
pub use registry_model::static_registry_version;
pub use registry_model::StaticRegistryEntry;
pub use registry_model::StaticRegistryKind;
pub use registry_model::StaticRegistryMatch;
pub use registry_model::StaticRegistryPatternKind;
pub use registry_model::StaticRegistryQuery;
pub use registry_model::STATIC_REGISTRY_VERSION;
