use super::*;

/// Synchronous, connection-owning finding/evidence store.
///
/// Access model: this store owns a single `rusqlite::Connection`, which is
/// `Send` but **not** `Sync`. Every method is blocking and must run on a thread
/// that owns the connection — the store must never be shared across threads
/// behind a shared reference, and its methods must never be `.await`-ed on a
/// runtime worker where they would block the async scheduler.
///
/// Async callers that need to read or write findings must therefore route the
/// call through a dedicated blocking boundary — either `tokio::task::spawn_blocking`
/// with an owned store, or an explicit `block_in_place` section (mirroring the
/// runtime's `isolate_blocking` shim) — rather than treating the connection as
/// if it were async-safe. WAL mode plus the configured `busy_timeout` (see
/// `configure_connection`) keep a second *process/connection* writer waiting
/// instead of erroring; they do not make one connection safe to share.
pub struct FindingStore {
    pub(crate) conn: Connection,
    pub(crate) db_path: Option<std::path::PathBuf>,
    pub(crate) event_log_dir: Option<std::path::PathBuf>,
    pub(crate) _ephemeral_dir: Option<tempfile::TempDir>,
}
