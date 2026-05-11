use super::availability::locate_joern_binary;
use kuzushi_mcp_common::doctor::{probe_all, HealthSummary};
use serde_json::{json, Value};
use std::time::Duration;

pub(crate) const PROBES: &[(&str, &[&str])] = &[
    ("joern", &["--version"]),
    ("joern-parse", &["--version"]),
    ("java", &["-version"]),
];

/// Slow + thorough: actually invokes `joern --version` etc. and
/// reports versions. Used by the standalone `kuzushi-mcp-joern --health`
/// CLI mode where startup latency is acceptable.
pub async fn health_summary() -> HealthSummary {
    probe_all(PROBES).await
}

/// Fast health for the `joern.health` MCP tool. The previous
/// implementation called `probe_all` which subprocess-execs each
/// binary with `--version`; on cold disk that's a JVM warm-up per
/// probe (~30s for `joern --version`) and tripped the agent's
/// per-tool timeout. The agent only needs three things to make a
/// decision: are the binaries on PATH, is a server already up, will
/// auto-spawn cover the gap. Resolve the first via PATH lookup
/// (microseconds), the second via a single 2s HTTP probe, and answer
/// the third with a static note. Operators who want full version
/// strings can still run `kuzushi-mcp-joern --health` from the CLI.
pub async fn extended_health() -> Value {
    let configured_url =
        std::env::var("JOERN_SERVER_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    let server_running = probe_server(&configured_url).await;
    let joern_path = locate_joern_binary("joern");
    let joern_parse_path = locate_joern_binary("joern-parse");
    let java_path = locate_joern_binary("java");
    let cpg_hint = std::env::var("KUZUSHI_JOERN_CPG").ok();
    let ready = joern_path.is_some() || joern_parse_path.is_some();
    json!({
        "ready": ready,
        "binaries": {
            "joern": joern_path.as_ref().map(|p| p.display().to_string()),
            "joernParse": joern_parse_path.as_ref().map(|p| p.display().to_string()),
            "java": java_path.as_ref().map(|p| p.display().to_string()),
        },
        "joernServerUrl": configured_url,
        "joernServerRunning": server_running,
        "kuzushiJoernCpg": cpg_hint,
        "autoSpawn": "Will be auto-spawned on first taint/query call if no server is running. Set KUZUSHI_JOERN_CPG=<path-to-cpg.bin> to importCpg the project at spawn time."
    })
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
