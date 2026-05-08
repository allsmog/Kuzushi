use super::prelude::*;
use super::*;

pub(crate) const PROBES: &[(&str, &[&str])] =
    &[("gtags", &["--version"]), ("global", &["--version"])];

pub async fn health_summary() -> HealthSummary {
    probe_all(PROBES).await
}
