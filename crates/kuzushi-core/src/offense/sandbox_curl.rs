//! A [`PlayTransport`] that sends requests with `curl` inside the sandbox.
//!
//! Live offensive traffic goes through the same isolation boundary as PoC
//! execution (`kuzushi-sandbox`), rather than pulling a heavyweight async HTTP
//! stack into the core. The request → `curl` argv translation and the
//! `curl -i` response parsing are pure functions (tested here); only the
//! actual `sandbox_exec` send needs a live target and an isolating backend.

use super::engagement_scope::ScopeTarget;
use super::transport::{PlayRequest, PlayResponse, PlayTransport};
use kuzushi_sandbox::{detect_backend, sandbox_exec, SandboxBackend, SandboxExecOptions};

/// Sends plays via `curl` in a network-enabled sandbox.
pub struct SandboxCurlTransport {
    backend: SandboxBackend,
    timeout_ms: u64,
}

impl SandboxCurlTransport {
    pub fn new(backend: SandboxBackend, timeout_ms: u64) -> Self {
        Self {
            backend,
            timeout_ms,
        }
    }

    /// Pick an isolating backend off PATH (bwrap/podman); falls back to
    /// `Plain` only if neither is present.
    pub fn detect(timeout_ms: u64) -> Self {
        Self::new(detect_backend(None), timeout_ms)
    }
}

impl PlayTransport for SandboxCurlTransport {
    fn send(&self, target: &ScopeTarget, request: &PlayRequest) -> Result<PlayResponse, String> {
        let options = SandboxExecOptions {
            cmd: build_curl_argv(target, request, self.timeout_ms),
            stdin: None,
            timeout_ms: self.timeout_ms,
            memory_mb: None,
            workdir: None,
            env: Default::default(),
            network: true,
            read_only_mounts: Vec::new(),
            read_write_mounts: Vec::new(),
        };
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| format!("offense transport could not start a tokio runtime: {err}"))?
            .block_on(sandbox_exec(self.backend, options))
            .map_err(|err| err.to_string())?;
        parse_curl_response(&result.stdout, result.duration_ms)
    }
}

/// The URL a request targets: `scheme://host[:port]/path`.
fn target_url(target: &ScopeTarget, request: &PlayRequest) -> String {
    let authority = match request.port {
        Some(port) => format!("{target}:{port}"),
        None => target.to_string(),
    };
    let path = if request.path.starts_with('/') {
        request.path.clone()
    } else {
        format!("/{}", request.path)
    };
    format!("{}://{}{}", request.scheme, authority, path)
}

/// Build the `curl` argv. `-i` includes response headers so the response can
/// be parsed; `-s -S` quiet the progress meter but keep errors. TLS
/// verification is left on by default.
fn build_curl_argv(target: &ScopeTarget, request: &PlayRequest, timeout_ms: u64) -> Vec<String> {
    let mut argv = vec![
        "curl".to_string(),
        "-i".to_string(),
        "-s".to_string(),
        "-S".to_string(),
        "--max-time".to_string(),
        timeout_seconds(timeout_ms).to_string(),
        "-X".to_string(),
        request.method.clone(),
    ];
    for (key, value) in &request.headers {
        argv.push("-H".to_string());
        argv.push(format!("{key}: {value}"));
    }
    if let Some(body) = &request.body {
        argv.push("--data-raw".to_string());
        argv.push(body.clone());
    }
    argv.push(target_url(target, request));
    argv
}

fn timeout_seconds(timeout_ms: u64) -> u64 {
    timeout_ms.div_ceil(1000).max(1)
}

/// Parse `curl -i` output (which may contain redirect/continue header blocks)
/// into the final response.
fn parse_curl_response(stdout: &str, elapsed_ms: u64) -> Result<PlayResponse, String> {
    let normalized = stdout.replace("\r\n", "\n");
    let block_start = last_status_block_start(&normalized)
        .ok_or_else(|| "curl produced no HTTP status line".to_string())?;
    let block = &normalized[block_start..];
    let (head, body) = match block.split_once("\n\n") {
        Some((head, body)) => (head, body.to_string()),
        None => (block, String::new()),
    };
    let mut lines = head.lines();
    let status = parse_status_line(lines.next().unwrap_or_default())?;
    let headers = parse_headers(lines);
    Ok(PlayResponse {
        status,
        headers,
        body,
        elapsed_ms,
    })
}

fn last_status_block_start(normalized: &str) -> Option<usize> {
    normalized.rmatch_indices("HTTP/").map(|(idx, _)| idx).next()
}

fn parse_status_line(line: &str) -> Result<u16, String> {
    line.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| format!("could not parse HTTP status from {line:?}"))
}

fn parse_headers<'a>(lines: impl Iterator<Item = &'a str>) -> Vec<(String, String)> {
    lines
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim().to_string(), value.trim().to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> ScopeTarget {
        ScopeTarget::parse("box.htb")
    }

    #[test]
    fn target_url_includes_scheme_port_and_path() {
        let request = PlayRequest {
            port: Some(8443),
            ..PlayRequest::get("admin")
        };
        assert_eq!(target_url(&target(), &request), "https://box.htb:8443/admin");
    }

    #[test]
    fn argv_carries_method_headers_body_and_url() {
        let request = PlayRequest::get("/login")
            .with_method("POST")
            .with_body("user=a&pass=b");
        let mut request = request;
        request.headers.push(("X-Test".to_string(), "1".to_string()));
        let argv = build_curl_argv(&target(), &request, 5_000);
        assert!(argv.contains(&"-X".to_string()) && argv.contains(&"POST".to_string()));
        assert!(argv.contains(&"X-Test: 1".to_string()));
        assert!(argv.contains(&"--data-raw".to_string()) && argv.contains(&"user=a&pass=b".to_string()));
        assert_eq!(argv.last().unwrap(), "https://box.htb/login");
        // 5000ms rounds to a 5s curl timeout.
        assert!(argv.contains(&"5".to_string()));
    }

    #[test]
    fn parses_a_simple_response() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Flag: win\r\n\r\n<h1>welcome admin</h1>";
        let response = parse_curl_response(raw, 12).unwrap();
        assert_eq!(response.status, 200);
        assert!(response.contains("welcome admin"));
        assert!(response.contains("win"));
        assert_eq!(response.elapsed_ms, 12);
    }

    #[test]
    fn parses_the_final_response_after_a_redirect() {
        let raw = "HTTP/1.1 302 Found\nLocation: /next\n\nHTTP/1.1 200 OK\nContent-Type: text/plain\n\nfinal body";
        let response = parse_curl_response(raw, 1).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, "final body");
    }

    #[test]
    fn missing_status_line_is_an_error() {
        assert!(parse_curl_response("garbage output", 1).is_err());
    }
}
