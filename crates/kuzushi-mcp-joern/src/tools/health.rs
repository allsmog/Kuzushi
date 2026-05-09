use kuzushi_mcp_common::doctor::{probe_all, HealthSummary};
use serde_json::{json, Value};
use std::time::Duration;

pub(crate) const PROBES: &[(&str, &[&str])] = &[
    ("joern", &["--version"]),
    ("joern-parse", &["--version"]),
    ("java", &["-version"]),
];

pub async fn health_summary() -> HealthSummary {
    probe_all(PROBES).await
}

/// Health response for the `joern.health` MCP tool. Combines the
/// binary-availability probes above with a live HTTP probe of the
/// joern REST server. Without the HTTP probe the tool used to claim
/// `ready: true` whenever the binaries existed, even when no server
/// was running — and the agent would dutifully call `joern.taint_paths`
/// only to get back `joern --server unreachable`.
pub async fn extended_health() -> Value {
    let summary = health_summary().await;
    let configured_url =
        std::env::var("JOERN_SERVER_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    let server_running = probe_server(&configured_url).await;
    let mut out = serde_json::to_value(&summary).unwrap_or(json!({}));
    if let Some(map) = out.as_object_mut() {
        map.insert("joernServerUrl".into(), json!(configured_url));
        map.insert("joernServerRunning".into(), json!(server_running));
        map.insert(
            "autoSpawn".into(),
            json!(
                "Will be auto-spawned on first taint/query call if not reachable. \
                 Set KUZUSHI_JOERN_CPG=<path-to-cpg.bin> to importCpg the project."
            ),
        );
    }
    out
}

async fn probe_server(url: &str) -> bool {
    let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
    else {
        return false;
    };
    matches!(client.get(url).send().await, Ok(_))
}
