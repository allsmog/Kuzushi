mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod items_1;
mod items_2;
mod items_3;
mod items_4;
#[cfg(test)]
mod tests;

pub use items_1::attach_source;
pub use items_1::attachment_store_path;
pub use items_1::detach_source;
pub use items_1::is_supported_attachment_module;
pub use items_1::list_attachments;
pub use items_1::AttachmentKind;
pub use items_1::AttachmentRecord;
pub use items_1::KnownArtifact;
pub use items_1::SUPPORTED_ATTACHMENT_MODULES;
pub use items_2::known_artifacts;
pub use items_2::reparse_source;
