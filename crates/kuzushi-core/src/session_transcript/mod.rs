//! Durable, operator-owned shell session transcripts.
//!
//! Session transcripts are global semantic audit logs. They intentionally do
//! not replace target-scoped run artifacts or the findings event log.

mod conversation;
pub mod lint;
mod model;
mod process_identity;
pub(crate) mod redaction;
mod session_lint;
mod store;
mod time;
mod writer;

pub use conversation::{ChatTurn, ConversationSnapshot, ThreadContextKey};
pub use lint::{lint_transcript, TranscriptLintReport};
pub use model::*;
pub use session_lint::{
    lint_session_records, SessionLintFinding, SessionLintKind, SessionLintOptions,
};
pub use store::{default_sessions_root, render_session_markdown, SessionTranscriptStore};
pub use time::{unix_seconds_from_timestamp, utc_timestamp_from_unix_seconds};
pub use writer::SessionRecorder;

pub const SESSION_TRANSCRIPT_SCHEMA_VERSION: u8 = 1;
pub const MAX_SESSION_RECORD_BYTES: usize = 1024 * 1024;
pub const DEFAULT_SESSION_RETENTION_DAYS: u64 = 30;

#[cfg(test)]
mod tests;
