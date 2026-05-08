use crate::workspace::WorkspaceTarget;
use anyhow::{Context, Result};
pub(crate) use attachment_id_error::*;
pub(crate) use attachment_store::*;
pub(crate) use build_url_record::*;
pub(crate) use reparse_source::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
mod attachment_id_error;
mod attachment_store;
mod build_url_record;
mod reparse_source;
#[cfg(test)]
mod tests;

pub use attachment_store::attach_source;
pub use attachment_store::attachment_store_path;
pub use attachment_store::detach_source;
pub use attachment_store::is_supported_attachment_module;
pub use attachment_store::list_attachments;
pub use attachment_store::AttachmentKind;
pub use attachment_store::AttachmentRecord;
pub use attachment_store::KnownArtifact;
pub use attachment_store::SUPPORTED_ATTACHMENT_MODULES;
pub use reparse_source::known_artifacts;
pub use reparse_source::reparse_source;
