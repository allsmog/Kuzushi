use super::prelude::*;
use super::*;

pub(crate) const PROBES: &[(&str, &[&str])] = &[
    ("joern", &["--version"]),
    ("joern-parse", &["--version"]),
    ("java", &["-version"]),
];

pub async fn health_summary() -> HealthSummary {
    probe_all(PROBES).await
}
