//! Shared access to the cross-language parity fixtures.
//!
//! The same files are asserted by `experiments/review-yield/tests/
//! test_parity_fixtures.py`. If one language passes and the other fails, the
//! canonical rule has drifted and one of the two is wrong.

use std::path::PathBuf;

use serde_json::Value;

pub(super) const PARITY_MODELS: [&str; 2] =
    ["model-numeric-small.json", "model-mixed-depth3.json"];

pub(super) fn parity_fixture_path(name: &str) -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../experiments/review-yield/fixtures/parity"
    ))
    .join(name)
}

pub(super) fn parity_bytes(name: &str) -> Vec<u8> {
    std::fs::read(parity_fixture_path(name)).expect("parity fixture is committed")
}

pub(super) fn parity_json(name: &str) -> Value {
    serde_json::from_slice(&parity_bytes(name)).expect("parity fixture is readable JSON")
}
