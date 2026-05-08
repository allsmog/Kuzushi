/// Configurable knobs for `verify_finding`. Defaults are chosen to be
/// safe in CI: Plain backend disallowed for promotion, 60-second cap.

/// Verify a finding by synthesising a harness, running it inside the
/// sandbox, and observing whether it crashes.
///
/// This is the entry point for the `verify:exploit` tool. The async
/// path branches by language; Rust, C, C++, Python, and JavaScript are
/// wired. Other languages return an `unsupported` outcome
/// (`proof_level=1`).

/// Rust verification path.
///
/// Synthesises a tiny `cargo` workspace under a temp dir that depends
/// on the suspect file's parent crate by path, declares one `#[test]`
/// that calls the suspect line directly with a generated trigger
/// payload, and runs `cargo test --offline` inside the sandbox. A
/// SIGABRT, SIGSEGV, or non-zero panic exit during the test phase
/// counts as exploited. Compile failure → `HarnessFailedToBuild`.

/// Outcome constructor for sandbox/infrastructure failures (couldn't
/// even spawn or scaffold). Always `proof_level=1`, verdict
/// `InfrastructureError`.

/// Outcome constructor for harness-compile failures. Reports the
/// compiler's stderr verbatim so callers can see why the trigger
/// didn't link.

/// Build the source for the trigger `#[test]`. When the suspect file is
/// readable, copies it into the harness as a `suspect` module and
/// synthesizes a call to the enclosing function with the payload. When
/// the signature shape isn't one we can construct an argument tuple
/// for, falls back to a payload-only harness with a comment recording
/// why.

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
mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod classification;

mod items_1;
mod items_2;
mod items_3;
mod items_4;
mod items_5;
mod items_6;
mod parse_rust_signature;
pub use parse_rust_signature::*;
pub(in crate::verify) use parse_rust_signature::*;
#[cfg(test)]
mod tests;

pub use classification::classify_run_result;
pub use items_1::ProofVerdict;
pub use items_1::VerificationOutcome;
pub use items_2::verify_finding;
pub use items_2::VerifyOptions;
pub(crate) use items_3::infer_language;
pub(crate) use items_3::Lang;
pub(crate) use items_6::RustSignature;
