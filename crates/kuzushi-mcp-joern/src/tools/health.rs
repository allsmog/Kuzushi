use kuzushi_mcp_common::doctor::{probe_all, HealthSummary};

pub(crate) const PROBES: &[(&str, &[&str])] = &[
    ("joern", &["--version"]),
    ("joern-parse", &["--version"]),
    ("java", &["-version"]),
];

pub async fn health_summary() -> HealthSummary {
    probe_all(PROBES).await
}
