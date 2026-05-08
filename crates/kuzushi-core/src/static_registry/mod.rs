mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod default_static_registry;
mod items_1;
mod items_2;
#[cfg(test)]
mod tests;

pub use items_1::default_static_registry;
pub use items_1::static_registry_version;
pub use items_1::StaticRegistryEntry;
pub use items_1::StaticRegistryKind;
pub use items_1::StaticRegistryMatch;
pub use items_1::StaticRegistryPatternKind;
pub use items_1::StaticRegistryQuery;
pub use items_1::STATIC_REGISTRY_VERSION;
pub use items_2::match_static_registry;
