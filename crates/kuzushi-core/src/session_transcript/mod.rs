//! Durable, operator-owned shell session transcripts.
//!
//! Session transcripts are global semantic audit logs. They intentionally do
//! not replace target-scoped run artifacts or the findings event log.

pub mod lint;
mod model;
mod process_identity;
pub(crate) mod redaction;
mod store;
mod time;
mod writer;

pub use lint::{lint_transcript, TranscriptLintReport};
pub use model::*;
pub use store::{default_sessions_root, render_session_markdown, SessionTranscriptStore};
pub use writer::SessionRecorder;

pub const SESSION_TRANSCRIPT_SCHEMA_VERSION: u8 = 1;
pub const MAX_SESSION_RECORD_BYTES: usize = 1024 * 1024;
pub const DEFAULT_SESSION_RETENTION_DAYS: u64 = 30;

#[cfg(test)]
mod tests;
