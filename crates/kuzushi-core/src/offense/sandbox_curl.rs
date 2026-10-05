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

    /// Pick an isolating backend off PATH (bwrap/podman). Backend detection can
    /// still return `Plain` when neither is installed, but sends to non-loopback
    /// targets fail closed before any process or network activity occurs.
    pub fn detect(timeout_ms: u64) -> Self {
        Self::new(detect_backend(None), timeout_ms)
    }

    pub fn backend(&self) -> SandboxBackend {
        self.backend
    }
}

impl PlayTransport for SandboxCurlTransport {
    fn send(&self, target: &ScopeTarget, request: &PlayRequest) -> Result<PlayResponse, String> {
        ensure_transport_isolation(self.backend, target)?;
        let options = SandboxExecOptions {
            cmd: build_curl_argv(target, request, self.timeout_ms)?,
            stdin: None,
            timeout_ms: self.timeout_ms,
            memory_mb: None,
            workdir: None,
            env: Default::default(),
            network: true,
            read_only_mounts: Vec::new(),
            read_write_mounts: Vec::new(),
        };
        let result = block_on_sandbox_exec(self.backend, options)?;
        completed_response(&result)
    }
}

/// The `Plain` backend executes directly on the operator host. It remains
/// useful for loopback labs, but live traffic to any other target must have an
/// isolating backend so a missing local dependency cannot silently weaken the
/// offense boundary.
fn ensure_transport_isolation(backend: SandboxBackend, target: &ScopeTarget) -> Result<(), String> {
    if backend != SandboxBackend::Plain || is_loopback_target(target) {
        return Ok(());
    }
    Err(format!(
        "offense transport refused {target}: no isolating sandbox backend is available; install bwrap or podman before sending live traffic to a non-loopback target"
    ))
}

fn is_loopback_target(target: &ScopeTarget) -> bool {
    match target {
        ScopeTarget::Ip(ip) => ip.is_loopback(),
        ScopeTarget::Host(host) => {
            host.eq_ignore_ascii_case("localhost")
                || host.to_ascii_lowercase().ends_with(".localhost")
        }
    }
}

/// Run the async `sandbox_exec` to completion from this synchronous trait
/// method. A dedicated thread with its own current-thread runtime is used so
/// this works whether or not the caller is already inside a tokio runtime
/// (the CLI dispatches tools from within one — building a runtime there and
/// blocking would panic with "Cannot start a runtime from within a runtime").
fn block_on_sandbox_exec(
    backend: SandboxBackend,
    options: SandboxExecOptions,
) -> Result<kuzushi_sandbox::SandboxExecResult, String> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|err| format!("offense transport could not start a runtime: {err}"))?
                    .block_on(sandbox_exec(backend, options))
                    .map_err(|err| err.to_string())
            })
            .join()
            .map_err(|_| "offense transport worker thread panicked".to_string())?
    })
}

/// The URL a request targets: `scheme://host[:port]/path`.
fn target_url(target: &ScopeTarget, request: &PlayRequest) -> Result<String, String> {
    target.validate()?;
    if !matches!(request.scheme.as_str(), "http" | "https") {
        return Err("offense requires an http or https scheme".into());
    }
    if request
        .path
        .chars()
        .any(|ch| ch.is_control() || ch == '\\' || ch == '#')
    {
        return Err("offense path contains a control, backslash, or fragment".into());
    }
    let authority = match target {
        ScopeTarget::Ip(std::net::IpAddr::V6(ip)) => format!("[{ip}]"),
        _ => target.to_string(),
    };
    let mut url = url::Url::parse(&format!("{}://{authority}/", request.scheme))
        .map_err(|error| format!("invalid offense URL: {error}"))?;
    url.set_port(request.port)
        .map_err(|_| "invalid offense port")?;
    let (path, query) = request
        .path
        .split_once('?')
        .map_or((request.path.as_str(), None), |(path, query)| {
            (path, Some(query))
        });
    url.set_path(path);
    url.set_query(query);
    let parsed = match url.host().ok_or("offense URL has no authority")? {
        url::Host::Domain(host) => ScopeTarget::parse(host),
        url::Host::Ipv4(ip) => ScopeTarget::Ip(ip.into()),
        url::Host::Ipv6(ip) => ScopeTarget::Ip(ip.into()),
    };
    if &parsed != target || !url.username().is_empty() || url.password().is_some() {
        return Err("offense URL authority differs from the authorized target".into());
    }
    Ok(url.into())
}

/// Build the `curl` argv. `-i` includes response headers so the response can
/// be parsed; `-s -S` quiet the progress meter but keep errors. TLS
/// verification is left on by default.
fn build_curl_argv(
    target: &ScopeTarget,
    request: &PlayRequest,
    timeout_ms: u64,
) -> Result<Vec<String>, String> {
    let mut argv = vec![
        "curl".to_string(),
        "--disable".to_string(),
        "--globoff".to_string(),
        "--proxy".to_string(),
        String::new(),
        "--noproxy".to_string(),
        "*".to_string(),
        "--suppress-connect-headers".to_string(),
        "--proto".to_string(),
        "=http,https".to_string(),
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
    argv.push("--".to_string());
    argv.push(target_url(target, request)?);
    Ok(argv)
}

fn timeout_seconds(timeout_ms: u64) -> u64 {
    timeout_ms.div_ceil(1000).max(1)
}

/// Parse `curl -i` output (which may contain redirect/continue header blocks)
/// into the final response.
fn completed_response(result: &kuzushi_sandbox::SandboxExecResult) -> Result<PlayResponse, String> {
    if result.outcome != kuzushi_sandbox::ExitOutcome::Exited
        || result.exit_code != Some(0)
        || result.stdout_truncated
        || result.stderr_truncated
    {
        return Err(format!("incomplete HTTP transfer: outcome={:?}, exit={:?}, signal={:?}, stdoutTruncated={}, stderrTruncated={}",
            result.outcome, result.exit_code, result.signal, result.stdout_truncated, result.stderr_truncated));
    }
    parse_curl_response(&result.stdout, result.duration_ms)
}

fn parse_curl_response(mut stdout: &str, elapsed_ms: u64) -> Result<PlayResponse, String> {
    loop {
        let (head, body) = split_http_headers(stdout)?;
        let mut lines = head.lines();
        let status = parse_status_line(lines.next().unwrap_or_default())?;
        if (100..200).contains(&status) {
            if status == 101 {
                return Err("HTTP protocol upgrade is unsupported".into());
            }
            stdout = body;
            continue;
        }
        return Ok(PlayResponse {
            status,
            headers: parse_headers(lines),
            body: body.to_string(),
            elapsed_ms,
        });
    }
}

fn split_http_headers(response: &str) -> Result<(&str, &str), String> {
    let boundary = response
        .find("\r\n\r\n")
        .map(|index| (index, 4))
        .into_iter()
        .chain(response.find("\n\n").map(|index| (index, 2)))
        .min_by_key(|(index, _)| *index);
    let (index, width) = boundary.ok_or("curl produced incomplete HTTP headers")?;
    Ok((&response[..index], &response[index + width..]))
}

fn parse_status_line(line: &str) -> Result<u16, String> {
    let mut parts = line.split_whitespace();
    if !matches!(
        parts.next(),
        Some("HTTP/1.0" | "HTTP/1.1" | "HTTP/2" | "HTTP/3")
    ) {
        return Err("curl produced no valid HTTP status line".into());
    }
    parts
        .next()
        .filter(|code| code.len() == 3)
        .and_then(|code| code.parse::<u16>().ok())
        .filter(|code| (100..=599).contains(code))
        .ok_or_else(|| "invalid HTTP status code".into())
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
        assert_eq!(
            target_url(&target(), &request).unwrap(),
            "https://box.htb:8443/admin"
        );
    }

    #[test]
    fn argv_carries_method_headers_body_and_url() {
        let request = PlayRequest::get("/login")
            .with_method("POST")
            .with_body("user=a&pass=b");
        let mut request = request;
        request
            .headers
            .push(("X-Test".to_string(), "1".to_string()));
        let argv = build_curl_argv(&target(), &request, 5_000).unwrap();
        assert!(argv.contains(&"-X".to_string()) && argv.contains(&"POST".to_string()));
        assert!(argv.contains(&"X-Test: 1".to_string()));
        assert!(
            argv.contains(&"--data-raw".to_string()) && argv.contains(&"user=a&pass=b".to_string())
        );
        assert_eq!(argv.last().unwrap(), "https://box.htb/login");
        // 5000ms rounds to a 5s curl timeout.
        assert!(argv.contains(&"5".to_string()));
    }

    #[test]
    fn plain_backend_refuses_non_loopback_before_process_or_network_activity() {
        let transport = SandboxCurlTransport::new(SandboxBackend::Plain, 5_000);
        let result = transport.send(&target(), &PlayRequest::get("/admin"));
        assert!(result.is_err());
        let error = result.err().unwrap();
        assert!(error.contains("offense transport refused box.htb"));
        assert!(error.contains("install bwrap or podman"));
    }

    #[test]
    fn plain_backend_allows_loopback_identity() {
        for raw in ["127.0.0.1", "::1", "localhost", "lab.localhost"] {
            assert!(
                ensure_transport_isolation(SandboxBackend::Plain, &ScopeTarget::parse(raw)).is_ok(),
                "{raw} should remain usable for a local lab"
            );
        }
    }

    #[test]
    fn isolating_backends_allow_remote_identity() {
        for backend in [SandboxBackend::Bwrap, SandboxBackend::Podman] {
            assert!(ensure_transport_isolation(backend, &target()).is_ok());
        }
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
    fn redirect_body_cannot_impersonate_a_second_response() {
        let raw = "HTTP/1.1 302 Found\nLocation: /next\n\nHTTP/1.1 200 OK\nContent-Type: text/plain\n\nfinal body";
        let response = parse_curl_response(raw, 1).unwrap();
        assert_eq!(response.status, 302);
        assert!(response.body.starts_with("HTTP/1.1 200 OK"));
    }

    #[test]
    fn missing_status_line_is_an_error() {
        assert!(parse_curl_response("garbage output", 1).is_err());
    }

    #[test]
    fn server_header_containing_http_does_not_fool_the_parser() {
        // A `Server` value with `HTTP/` in it (e.g. Python's BaseHTTP/0.6)
        // must not be mistaken for the status line.
        let raw = "HTTP/1.0 200 OK\r\nServer: BaseHTTP/0.6 Python/3.11\r\n\r\nuid=0(root)";
        let response = parse_curl_response(raw, 3).unwrap();
        assert_eq!(response.status, 200);
        assert!(response.contains("uid=0(root)"));
    }
}

#[cfg(test)]
mod audit_regressions {
    use super::*;
    #[test]
    fn malicious_authorities_and_schemes_are_rejected() {
        for host in [
            "outside.example/?x=.allowed.example",
            "user@allowed.example",
            "allowed.example#x",
            "allowed.example:443",
            "127.1",
        ] {
            assert!(
                target_url(&ScopeTarget::parse(host), &PlayRequest::get("/")).is_err(),
                "{host}"
            );
        }
        let mut request = PlayRequest::get("/");
        request.scheme = "https://outside.example/?ignored=".into();
        assert!(target_url(&ScopeTarget::parse("allowed.example"), &request).is_err());
    }
    #[test]
    fn ipv6_and_literal_globs_have_one_explicit_transport_request() {
        let request = PlayRequest::get("/a[1-9]/{x,y}?q=1");
        let args = build_curl_argv(&ScopeTarget::parse("::1"), &request, 1000).unwrap();
        assert_eq!(args[1], "--disable");
        assert!(args.iter().any(|a| a == "--globoff"));
        assert_eq!(args[args.len() - 2], "--");
        assert!(args.last().unwrap().starts_with("https://[::1]/"));
    }
    #[test]
    fn response_body_is_not_protocol_and_retains_crlf() {
        let body = "denied\r\nHTTP/1.1 200 OK\r\n\r\nforged";
        let response =
            parse_curl_response(&format!("HTTP/1.1 403 Forbidden\r\n\r\n{body}"), 0).unwrap();
        assert_eq!(response.status, 403);
        assert_eq!(response.body, body);
        assert_eq!(
            parse_curl_response(
                "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\n\r\nok",
                0
            )
            .unwrap()
            .status,
            201
        );
    }
    #[test]
    fn unsuccessful_and_truncated_transfers_cannot_be_successes() {
        for (exit, truncated) in [(Some(18), false), (Some(0), true)] {
            let result = kuzushi_sandbox::SandboxExecResult {
                backend: SandboxBackend::Plain,
                outcome: kuzushi_sandbox::ExitOutcome::Exited,
                exit_code: exit,
                signal: None,
                stdout: "HTTP/1.1 200 OK\r\n\r\npartial".into(),
                stderr: String::new(),
                stdout_truncated: truncated,
                stderr_truncated: false,
                duration_ms: 0,
            };
            assert!(completed_response(&result).is_err());
        }
    }
}
