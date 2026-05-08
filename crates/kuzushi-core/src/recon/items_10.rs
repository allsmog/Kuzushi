use super::prelude::*;
use super::*;

pub(crate) fn parse_wayback_subdomains(stdout: &str, domain: &str) -> Result<Vec<String>> {
    if stdout.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut domains = BTreeSet::new();
    if let Ok(value) = serde_json::from_str::<Value>(stdout) {
        if let Some(rows) = value.as_array() {
            for row in rows {
                if let Some(url) = row.as_str().or_else(|| {
                    row.as_array()
                        .and_then(|values| values.first())
                        .and_then(Value::as_str)
                }) {
                    if url.eq_ignore_ascii_case("original") {
                        continue;
                    }
                    if let Some(host) =
                        host_from_url(url).and_then(|host| normalize_subdomain(&host, domain))
                    {
                        domains.insert(host);
                    }
                }
            }
            return Ok(domains.into_iter().collect());
        }
    }

    for line in stdout.lines() {
        if let Some(host) = host_from_url(line).and_then(|host| normalize_subdomain(&host, domain))
        {
            domains.insert(host);
        }
    }
    Ok(domains.into_iter().collect())
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct HttpFingerprint {
    pub(crate) status: Option<u16>,
    pub(crate) headers: BTreeMap<String, String>,
    pub(crate) server: Option<String>,
    pub(crate) title: Option<String>,
    pub(crate) technologies: Vec<String>,
}

pub(crate) fn parse_http_fingerprint(stdout: &str) -> Result<HttpFingerprint> {
    let (headers_raw, body) = split_last_http_response(stdout);
    let mut status = None;
    let mut headers = BTreeMap::new();
    for line in headers_raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("HTTP/") {
            status = trimmed
                .split_whitespace()
                .nth(1)
                .and_then(|value| value.parse::<u16>().ok());
            continue;
        }
        if let Some((key, value)) = trimmed.split_once(':') {
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            if !key.is_empty() {
                headers.insert(key, value);
            }
        }
    }
    let server = headers.get("server").cloned();
    let title = extract_html_title(body);
    let technologies = infer_http_technologies(&headers, body);
    Ok(HttpFingerprint {
        status,
        headers,
        server,
        title,
        technologies,
    })
}

pub(crate) fn split_last_http_response(stdout: &str) -> (&str, &str) {
    let marker = "\r\n\r\n";
    let normalized_marker = "\n\n";
    if let Some((headers, body)) = stdout.rsplit_once(marker) {
        return (last_http_header_block(headers), body);
    }
    if let Some((headers, body)) = stdout.rsplit_once(normalized_marker) {
        return (last_http_header_block(headers), body);
    }
    (stdout, "")
}

pub(crate) fn last_http_header_block(headers: &str) -> &str {
    headers
        .rsplit("\r\n\r\n")
        .next()
        .unwrap_or(headers)
        .rsplit("\n\n")
        .next()
        .unwrap_or(headers)
}

pub(crate) fn extract_html_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let start = lower.find("<title>")?;
    let end = lower[start + 7..].find("</title>")? + start + 7;
    Some(body[start + 7..end].trim().to_string()).filter(|title| !title.is_empty())
}
