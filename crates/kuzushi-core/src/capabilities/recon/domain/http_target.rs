use super::*;
use url::{Host, Url};

pub(crate) fn host_from_url(url: &str) -> Option<String> {
    let without_scheme = url
        .trim()
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or_else(|| url.trim());
    // Cut the authority at the first path/query/fragment delimiter BEFORE
    // stripping credentials: an `@` later in the URL
    // (`https://evil.test/@in-scope.host`) must not spoof the host.
    let authority = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, rest)| rest)
        .unwrap_or(authority);
    let host = host_port.split(':').next().unwrap_or_default().trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// The endpoint an HTTP fetch actually spoke to, read from the URL that fetch
/// used rather than from the operator's spelling of the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Endpoint {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) scheme: String,
}

/// Read a free-form `recon:http-fingerprint` target as the absolute URL curl
/// will fetch. A target no HTTP client can read is refused here rather than
/// guessed at: the previous reading substituted the scheme's default port for
/// an unparseable one, so `example.com:99999` registered a service on port 80
/// that nothing had probed.
pub(crate) fn http_target_url(target: &str) -> Result<Url> {
    let trimmed = target.trim();
    let candidate = match http_scheme_spelled(trimmed) {
        Some(false) => anyhow::bail!(
            "recon:http-fingerprint target {target:?} is not an http or https URL"
        ),
        Some(true) => trimmed.to_string(),
        None => format!("http://{trimmed}"),
    };
    Url::parse(&candidate).with_context(|| {
        format!("recon:http-fingerprint could not read target {target:?} as an HTTP URL")
    })
}

/// `Some(true)` when the target spells an http or https scheme, `Some(false)`
/// for any other explicit scheme, `None` when it spells none.
fn http_scheme_spelled(target: &str) -> Option<bool> {
    let (scheme, _) = target.split_once("://")?;
    Some(matches!(
        scheme.to_ascii_lowercase().as_str(),
        "http" | "https"
    ))
}

/// The host, port, and scheme a fetched URL names. `port_or_known_default` is
/// total for the two HTTP schemes, and an IPv6 literal is recorded as the
/// address it is rather than the brackets an authority spells it with.
pub(crate) fn endpoint_from_url(url: &Url) -> Result<Endpoint> {
    let host = match url.host() {
        Some(Host::Ipv6(address)) => address.to_string(),
        Some(host) => host.to_string(),
        None => anyhow::bail!("recon:http-fingerprint URL {url} names no host"),
    };
    let port = url
        .port_or_known_default()
        .with_context(|| format!("recon:http-fingerprint URL {url} names no port"))?;
    Ok(Endpoint {
        host,
        port,
        scheme: url.scheme().to_string(),
    })
}

pub(crate) fn now_isoish() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    format!("{seconds}")
}

pub(crate) fn plural(count: usize) -> &'static str {
    if count == 1 {
        ""
    } else {
        "s"
    }
}

#[cfg(test)]
mod http_target_tests {
    use super::*;

    #[test]
    fn host_from_url_handles_schemes_credentials_and_ports() {
        assert_eq!(
            host_from_url("https://user:pw@API.Example.com:8443/path?q=1"),
            Some("api.example.com".to_string())
        );
        assert_eq!(host_from_url("example.com/path"), Some("example.com".to_string()));
        assert_eq!(host_from_url("   "), None);
    }

    #[test]
    fn http_target_url_keeps_the_scheme_and_port_the_operator_named() {
        assert_eq!(
            http_target_url(" example.com ").unwrap().as_str(),
            "http://example.com/"
        );
        assert_eq!(
            http_target_url("https://example.com:8443/x")
                .unwrap()
                .as_str(),
            "https://example.com:8443/x"
        );
        let refused = http_target_url("ftp://files.example.com")
            .unwrap_err()
            .to_string();
        assert!(refused.contains("not an http or https URL"), "got: {refused}");
    }

    #[test]
    fn an_unreadable_port_is_refused_rather_than_read_as_the_default() {
        // The previous reading parsed the port with `unwrap_or(default_port)`,
        // so this target registered a service on port 80 that nothing probed.
        let error = http_target_url("example.com:99999").unwrap_err().to_string();
        assert!(error.contains("could not read target"), "got: {error}");
    }

    #[test]
    fn endpoint_from_url_reads_host_port_and_scheme() {
        let endpoint = endpoint_from_url(&http_target_url("https://example.com").unwrap()).unwrap();
        assert_eq!(endpoint.host, "example.com");
        assert_eq!(endpoint.port, 443);
        assert_eq!(endpoint.scheme, "https");

        let plain = endpoint_from_url(&http_target_url("example.com:8080").unwrap()).unwrap();
        assert_eq!(plain.port, 8080);
        assert_eq!(plain.scheme, "http");
    }

    #[test]
    fn endpoint_from_url_records_an_ipv6_literal_as_its_address() {
        let endpoint = endpoint_from_url(&http_target_url("http://[2001:db8::1]:8443").unwrap())
            .unwrap();
        assert_eq!(endpoint.host, "2001:db8::1");
        assert_eq!(endpoint.port, 8443);
    }

    #[test]
    fn host_from_url_is_not_spoofed_by_at_signs_after_the_authority() {
        assert_eq!(
            host_from_url("https://evil.test/@api.example.com"),
            Some("evil.test".to_string())
        );
        assert_eq!(
            host_from_url("https://evil.test/?next=user@api.example.com"),
            Some("evil.test".to_string())
        );
        assert_eq!(
            host_from_url("https://evil.test/#user@api.example.com"),
            Some("evil.test".to_string())
        );
    }
}

pub(crate) fn normalize_subdomain(candidate: &str, domain: &str) -> Option<String> {
    let host = candidate
        .trim()
        .trim_end_matches('.')
        .trim_start_matches("*.")
        .to_ascii_lowercase();
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if host == domain || !host.ends_with(&format!(".{domain}")) {
        return None;
    }
    Some(host)
}
