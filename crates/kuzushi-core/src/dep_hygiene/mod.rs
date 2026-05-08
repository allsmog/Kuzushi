/// Ground-truth Rust supply-chain scanner backed by `cargo audit --json`.
///
/// Mirrors the Xint Code design instinct of preferring deterministic scanner
/// output over LLM-rediscovered manifest patterns. Runs only when the target
/// has a `Cargo.lock` and the `cargo-audit` binary is on PATH; otherwise
/// returns no findings (the legacy text-parse path in `DepHygieneScanner`
/// remains the fallback).

/// Parse a `cargo audit --json` document into core `Finding`s.
///
/// Public for testing and for any future direct-pipe callers (e.g. CI feeding
/// pre-captured advisories into the findings store without re-running cargo).
mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod analyze_package_json;
mod analyze_pep508;
mod analyze_pyproject_toml;
mod items_1;
mod items_2;
mod items_3;
mod items_4;
pub use analyze_pep508::*;
#[cfg(test)]
mod tests;

pub use items_1::DepHygieneFinding;
pub use items_1::DepHygieneReport;
pub use items_2::CargoAuditScanner;
pub use items_2::DepHygieneScanner;
pub use items_2::DepHygieneSeverity;
pub use items_3::parse_cargo_audit_output;
pub use items_4::analyze_manifest;
pub use items_4::check_dependency_hygiene;
pub use items_4::ManifestKind;
