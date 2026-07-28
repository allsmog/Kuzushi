/// Configurable knobs for `verify_finding`. Defaults are chosen to be
/// safe in CI: Plain backend disallowed for execution, 60-second cap.

/// Verify a finding by synthesising a harness, running it inside the
/// sandbox, and observing whether it crashes.
///
/// This is the entry point for the `verify:exploit` tool. The async
/// path branches by language. Faithful Rust, C, and C++ harnesses may run;
/// Python, JavaScript, TypeScript, and payload-only fallbacks return
/// `NotAttempted`. Other languages return an `unsupported` outcome.

/// Rust verification path.
///
/// Synthesises a tiny `cargo` workspace under a temp dir, copies a
/// self-contained suspect module, and declares one `#[test]` that calls
/// the sink with a generated trigger payload. Only an isolating sandbox
/// with durable reached-sink evidence can produce a runtime verdict.

/// Outcome constructor for sandbox/infrastructure failures (couldn't
/// even spawn or scaffold). Always `proof_level=1`, verdict
/// `InfrastructureError`.

/// Outcome constructor for harness-compile failures. Reports the
/// bounded, redacted compiler stderr so callers can diagnose why the
/// trigger didn't link.

/// Build the source for the trigger `#[test]`. When the suspect file is
/// readable, copies it into the harness as a `suspect` module and
/// synthesizes a call to the enclosing function with the payload. When
/// the signature shape isn't one we can construct an argument tuple
/// for, marks the trigger payload-only so verification stops before
/// compile or execution.

/// Quick screen for whether copying the suspect file alone is likely to
/// give the harness a chance of building. Refuses copies that import
/// non-standard crates or use proc macros that we can't replicate
/// without the parent crate's full `Cargo.toml`.

/// Parsed signature we can use to plan a call. Keep the structure
/// minimal — argument *names* don't matter for synthesis, only types.

/// Parse a single-line Rust function signature like
/// `pub fn parse_packet(input: &[u8], n: usize) -> Result<u32>` into a
/// `RustSignature`. Returns `None` when the input doesn't look like a
/// `fn` declaration our caller can use.
use crate::findings::{
    Finding, PersistedProofVerdict, PersistedSandboxBackend, PersistedVerification,
};
use anyhow::{Context, Result};
pub(in crate::verification) use build_rust_trigger::*;
pub(in crate::verification) use compile_failure_outcome::*;
pub(crate) use infer_language::*;
use kuzushi_sandbox::{
    detect_backend, sandbox_exec, MountSpec, SandboxBackend, SandboxExecOptions,
};
pub(crate) use rust_source_appears_self_contained::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
pub(crate) mod adapters;
pub mod application;
mod classification;
pub mod domain;
pub mod sandbox;

mod build_rust_trigger;
mod compile_failure_outcome;
mod infer_language;
mod parse_rust_signature;
mod provenance;
mod rust_source_appears_self_contained;
mod unsupported;
mod verification_outcome;
pub use parse_rust_signature::*;
#[cfg(test)]
mod tests;

pub(crate) use adapters::DEFAULT_VERIFY_PROMPT;
pub(in crate::verification) use classification::{
    bounded_runtime_evidence, configure_sink_marker, not_attempted_for_harness,
    prepare_sink_marker, SINK_MARKER_CONTENT,
};
pub use classification::{classify_run_result, HarnessFidelity};
pub(crate) use infer_language::infer_language;
pub(crate) use infer_language::Lang;
pub(crate) use provenance::*;
pub(crate) use rust_source_appears_self_contained::RustSignature;
pub use unsupported::verify_finding;
pub(crate) use unsupported::verify_finding_with_payload;
pub use unsupported::VerifyOptions;
pub use verification_outcome::ProofVerdict;
pub use verification_outcome::VerificationOutcome;
