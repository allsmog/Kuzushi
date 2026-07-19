use crate::ServerInfo;
use anyhow::Result;
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StandaloneHealth<'a> {
    server: &'a str,
    version: &'a str,
    process_healthy: bool,
    protocol: &'static str,
    backend_readiness: &'static str,
}

/// Report process/protocol liveness without claiming that optional external
/// tools or target-specific capabilities are available.
pub fn exit_after_standalone_health_if_requested(info: &ServerInfo) -> Result<()> {
    if !std::env::args_os().any(|argument| argument == "--health") {
        return Ok(());
    }
    let health = StandaloneHealth {
        server: &info.name,
        version: &info.version,
        process_healthy: true,
        protocol: "stdio",
        backend_readiness: "not-probed",
    };
    println!("{}", serde_json::to_string_pretty(&health)?);
    std::process::exit(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_health_does_not_claim_unprobed_backend_readiness() {
        let health = StandaloneHealth {
            server: "kuzushi-mcp-test",
            version: "1.2.3",
            process_healthy: true,
            protocol: "stdio",
            backend_readiness: "not-probed",
        };

        let value = serde_json::to_value(health).unwrap();

        assert_eq!(value["server"], "kuzushi-mcp-test");
        assert_eq!(value["version"], "1.2.3");
        assert_eq!(value["processHealthy"], true);
        assert_eq!(value["protocol"], "stdio");
        assert_eq!(value["backendReadiness"], "not-probed");
        assert_eq!(value.get("ready"), None);
    }
}
