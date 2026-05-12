//! Thin re-export to keep the original `kuzushi_cli::wants_sast_runtime`
//! call sites compiling. The rule moved to
//! `kuzushi_core::wants_sast_runtime` so the TUI can apply the same
//! input nuance to `sast:scan` runtime construction. See
//! `crates/kuzushi-core/src/modules/runtime_requirements.rs` for the
//! authoritative definition.

pub(crate) use kuzushi_core::wants_sast_runtime;
