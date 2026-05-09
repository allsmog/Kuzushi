use super::*;

pub(crate) fn host_from_url(url: &str) -> Option<String> {
    let without_scheme = url
        .trim()
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or_else(|| url.trim());
    let without_credentials = without_scheme
        .rsplit_once('@')
        .map(|(_, rest)| rest)
        .unwrap_or(without_scheme);
    let host_port = without_credentials
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    let host = host_port.split(':').next().unwrap_or_default().trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Endpoint {
    pub(crate) host: String,
    pub(crate) port: u16,
}

pub(crate) fn split_host_port(target: &str) -> Endpoint {
    let default_port = if target.starts_with("https://") {
        443
    } else {
        80
    };
    let without_scheme = target
        .trim()
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or_else(|| target.trim());
    let host_port = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(without_scheme);
    let (host, port) = if let Some((host, port)) = host_port.rsplit_once(':') {
        let parsed = port.parse::<u16>().ok().unwrap_or(default_port);
        (host.to_string(), parsed)
    } else {
        (host_port.to_string(), default_port)
    };
    Endpoint { host, port }
}

pub(crate) fn ensure_http_scheme(target: &str) -> String {
    if target.starts_with("http://") || target.starts_with("https://") {
        target.to_string()
    } else {
        format!("http://{target}")
    }
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
