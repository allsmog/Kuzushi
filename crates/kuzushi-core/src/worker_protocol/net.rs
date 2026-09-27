use super::{
    check_u64, KwpError, NetFetchRequest, NetFetchResult, ValidatedNetFetch,
    KWP_MAX_NETWORK_RESPONSE_BYTES,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::Read;
use std::net::SocketAddr;
use std::time::Duration;

pub(super) const DEFAULT_NET_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_SESSION_CLIENTS: usize = 16;

#[derive(Default)]
pub(super) struct PinnedHttpClientPool {
    clients: HashMap<NetClientKey, reqwest::blocking::Client>,
    recency: VecDeque<NetClientKey>,
}

impl PinnedHttpClientPool {
    pub(super) fn fetch(
        &mut self,
        checked: ValidatedNetFetch,
        timeout: Duration,
    ) -> Result<NetFetchResult, KwpError> {
        let client = self.client_for(&checked, timeout)?;
        let request = build_net_request(&client, &checked.request)?;
        let response = request
            .send()
            .map_err(|error| KwpError::Internal(error.to_string()))?;
        net_fetch_result(response, checked.response_byte_limit)
    }

    fn client_for(
        &mut self,
        checked: &ValidatedNetFetch,
        timeout: Duration,
    ) -> Result<reqwest::blocking::Client, KwpError> {
        let key = NetClientKey::from_checked(checked, timeout);
        if let Some(client) = self.clients.get(&key) {
            let client = client.clone();
            self.touch(&key);
            return Ok(client);
        }
        let client = build_net_client(&key)?;
        self.clients.insert(key.clone(), client.clone());
        self.touch(&key);
        self.evict_overflow();
        Ok(client)
    }

    fn touch(&mut self, key: &NetClientKey) {
        self.recency.retain(|candidate| candidate != key);
        self.recency.push_back(key.clone());
    }

    fn evict_overflow(&mut self) {
        while self.clients.len() > MAX_SESSION_CLIENTS {
            if let Some(oldest) = self.recency.pop_front() {
                self.clients.remove(&oldest);
            }
        }
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.clients.len()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct NetClientKey {
    host: String,
    pinned_addr: SocketAddr,
    timeout: Duration,
    policy: NetTransportPolicy,
}

impl NetClientKey {
    fn from_checked(checked: &ValidatedNetFetch, timeout: Duration) -> Self {
        Self {
            host: checked.endpoint.host.clone(),
            pinned_addr: checked.pinned_addr,
            timeout,
            policy: NetTransportPolicy::HttpsNoRedirect,
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum NetTransportPolicy {
    HttpsNoRedirect,
}

/// The client dials only the validated, pinned address. Proxy environment
/// variables are ignored: a proxy would re-resolve the host itself and bypass
/// the address that brokered egress validated.
fn build_net_client(key: &NetClientKey) -> Result<reqwest::blocking::Client, KwpError> {
    reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(key.timeout)
        .resolve(&key.host, key.pinned_addr)
        .build()
        .map_err(|error| KwpError::Internal(error.to_string()))
}

fn build_net_request(
    client: &reqwest::blocking::Client,
    input: &NetFetchRequest,
) -> Result<reqwest::blocking::RequestBuilder, KwpError> {
    let method = reqwest::Method::from_bytes(input.method.as_bytes())
        .map_err(|error| KwpError::BadRequest(error.to_string()))?;
    let mut request = client.request(method, &input.url);
    for (name, value) in &input.headers {
        let header_name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|error| KwpError::BadRequest(error.to_string()))?;
        let header_value = reqwest::header::HeaderValue::from_str(value)
            .map_err(|error| KwpError::BadRequest(error.to_string()))?;
        request = request.header(header_name, header_value);
    }
    if let Some(body) = input.body_base64.as_ref() {
        let body = BASE64
            .decode(body.as_bytes())
            .map_err(|error| KwpError::BadRequest(error.to_string()))?;
        request = request.body(body);
    }
    Ok(request)
}

fn net_fetch_result(
    response: reqwest::blocking::Response,
    grant_limit: Option<u64>,
) -> Result<NetFetchResult, KwpError> {
    let status = response.status().as_u16();
    let headers = response_headers(response.headers());
    let response_byte_limit = effective_net_response_limit(grant_limit);
    check_u64(
        response.content_length(),
        Some(response_byte_limit),
        "net.bytes",
    )?;
    let body = read_net_response_body(response, Some(response_byte_limit))?;
    Ok(NetFetchResult {
        status,
        headers,
        body_base64: Some(BASE64.encode(body)),
        artifact: None,
    })
}

pub(super) fn effective_net_response_limit(grant_limit: Option<u64>) -> u64 {
    grant_limit
        .unwrap_or(KWP_MAX_NETWORK_RESPONSE_BYTES)
        .min(KWP_MAX_NETWORK_RESPONSE_BYTES)
}

pub(super) fn read_net_response_body<R: Read>(
    mut reader: R,
    limit: Option<u64>,
) -> Result<Vec<u8>, KwpError> {
    let mut body = Vec::new();
    if let Some(limit) = limit {
        let mut limited = reader.by_ref().take(limit.saturating_add(1));
        limited
            .read_to_end(&mut body)
            .map_err(|error| KwpError::Internal(error.to_string()))?;
        check_u64(Some(body.len() as u64), Some(limit), "net.bytes")?;
        return Ok(body);
    }
    reader
        .read_to_end(&mut body)
        .map_err(|error| KwpError::Internal(error.to_string()))?;
    Ok(body)
}

fn response_headers(headers: &reqwest::header::HeaderMap) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_string(), value.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker_protocol::{NetEndpoint, NetFetchRequest};

    #[test]
    fn equivalent_keys_reuse_clients_and_pin_or_timeout_changes_do_not() {
        let mut pool = PinnedHttpClientPool::default();
        let base = checked("93.184.216.34:443", None);
        pool.client_for(&base, DEFAULT_NET_TIMEOUT).unwrap();
        pool.client_for(&base, DEFAULT_NET_TIMEOUT).unwrap();
        assert_eq!(pool.len(), 1);

        let changed_pin = checked("93.184.216.35:443", None);
        pool.client_for(&changed_pin, DEFAULT_NET_TIMEOUT).unwrap();
        pool.client_for(&base, Duration::from_millis(1_000))
            .unwrap();

        assert_eq!(pool.len(), 3);
    }

    #[test]
    fn client_pool_evicts_old_keys_at_the_session_bound() {
        let mut pool = PinnedHttpClientPool::default();
        for offset in 0..MAX_SESSION_CLIENTS + 5 {
            pool.client_for(
                &checked("93.184.216.34:443", None),
                Duration::from_millis(1_000 + offset as u64),
            )
            .unwrap();
        }

        assert_eq!(pool.len(), MAX_SESSION_CLIENTS);
    }

    #[test]
    fn hanging_tls_peer_is_bounded_by_the_effective_worker_timeout() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let pinned_addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let peer = std::thread::spawn(move || accept_then_stall(&listener));
        let mut checked = checked(&pinned_addr.to_string(), None);
        checked.request.url = format!("https://example.com:{}/", pinned_addr.port());
        checked.endpoint.port = pinned_addr.port();
        let started = std::time::Instant::now();

        let error = PinnedHttpClientPool::default()
            .fetch(checked, Duration::from_millis(40))
            .unwrap_err();

        assert!(matches!(error, KwpError::Internal(_)));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(
            peer.join().unwrap(),
            "the client must dial the pinned address directly, even with a proxy configured"
        );
    }

    /// Accept one connection within a deadline, then hold it without speaking
    /// TLS. Returns whether any client dialed the listener.
    fn accept_then_stall(listener: &std::net::TcpListener) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while std::time::Instant::now() < deadline {
            if let Ok((_stream, _)) = listener.accept() {
                std::thread::sleep(Duration::from_millis(500));
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    fn checked(pinned: &str, timeout_ms: Option<u64>) -> ValidatedNetFetch {
        ValidatedNetFetch {
            request: NetFetchRequest {
                method: "GET".to_string(),
                url: "https://example.com/".to_string(),
                headers: BTreeMap::new(),
                body_base64: None,
                timeout_ms,
                credential_name: None,
                response_artifact_path: None,
                response_media_type: None,
            },
            endpoint: NetEndpoint {
                host: "example.com".to_string(),
                port: 443,
            },
            pinned_addr: pinned.parse().unwrap(),
            response_byte_limit: None,
        }
    }
}
