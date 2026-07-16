mod envelope;
mod ids;
mod item;
mod policy;
mod safe_text;

pub use envelope::{RunItemEnvelopeV1, RunItemRecord, RunItemSource, RUN_ITEM_SCHEMA_VERSION};
pub use ids::*;
pub use item::*;
pub use policy::{PersistenceClass, RunItemPersistencePolicy};
pub use safe_text::{SafeText, MAX_PREVIEW_LINE_CHARS, RUN_ITEM_REDACTION_POLICY_VERSION};

pub const MAX_SERIALIZED_RUN_ITEM_BYTES: usize = 64 * 1024;
pub const MAX_RUN_ITEM_STREAM_BYTES: u64 = 64 * 1024 * 1024;
pub const RUN_ITEM_CRITICAL_RESERVE_BYTES: u64 = 1024 * 1024;
