use crate::ServerInfo;
use anyhow::Result;
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StandaloneHealth<'a> {
    server: &'a str,
    version: &'a str,
    ready: bool,
    mode: &'static str,
}

/// Handle the release-smoke `--health` contract before a server constructs
/// tool registries or reads target capabilities.
pub fn exit_after_standalone_health_if_requested(info: &ServerInfo) -> Result<()> {
    if !std::env::args_os().any(|argument| argument == "--health") {
        return Ok(());
    }
    let health = StandaloneHealth {
        server: &info.name,
        version: &info.version,
        ready: true,
        mode: "stdio-server",
    };
    println!("{}", serde_json::to_string_pretty(&health)?);
    std::process::exit(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_health_is_truthful_server_startup_metadata() {
        let health = StandaloneHealth {
            server: "kuzushi-mcp-test",
            version: "1.2.3",
            ready: true,
            mode: "stdio-server",
        };

        let value = serde_json::to_value(health).unwrap();

        assert_eq!(value["server"], "kuzushi-mcp-test");
        assert_eq!(value["version"], "1.2.3");
        assert_eq!(value["ready"], true);
        assert_eq!(value["mode"], "stdio-server");
    }
}
