//! Remote execution plane for kuzushi fleets (CLI-only; the TUI reads its
//! artifacts, never this crate).
//!
//! Strict transport/judgment split: this crate moves bits, launches queues,
//! and reports state. It contains zero scanning knowledge. Every verb
//! encodes an operational scar from the fleet-orchestration lineage:
//! - `stage` refuses a checkout that is behind its upstream, refuses to
//!   re-stage over live sessions without `--force`, and every transfer is
//!   loud-fail (a silent scp failure once re-ran a stale queue).
//! - `status` is zombie-aware: a tmux session existing is not the same as
//!   the engine process being alive.
//! - `pull` applies a recency cutoff by default so stale runs are not
//!   re-ingested under today's date, and writes a `MANIFEST.json`.
//! - Credentialed side effects never run remotely or unattended.

pub mod config;
pub mod doctor;
pub mod launch;
pub mod pull;
pub mod stage;
pub mod status;
pub mod transport;

pub use config::{load_remotes, RemoteBox};
pub use transport::{CommandOutput, SshTransport, Transport};
