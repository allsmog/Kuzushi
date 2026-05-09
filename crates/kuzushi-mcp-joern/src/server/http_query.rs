use anyhow::{Context, Result};

pub async fn run_query(scala: &str) -> Result<String> {
    // ensure_joern_server() respects an operator-set JOERN_SERVER_URL
    // when reachable, otherwise lazy-spawns a child process owned by
    // the MCP server's lifetime. After the call, JOERN_SERVER_URL is
    // pinned to a known-good URL for the rest of this process.
    let url = super::auto_spawn::ensure_joern_server().await?;
    let client = joern_http_client()?;
    let response = send_joern_query(&client, &url, scala).await?;
    read_joern_response(response).await
}

/// Default URL the auto-spawn module pins JOERN_SERVER_URL to. Kept
/// here (rather than dropped) so doctor/tests can probe a sensible
/// default when no server is running.
#[allow(dead_code)]
pub(crate) fn joern_server_url() -> String {
    std::env::var("JOERN_SERVER_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string())
}

pub(crate) fn joern_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .context("could not build joern HTTP client")
}

pub(crate) async fn send_joern_query(
    client: &reqwest::Client,
    url: &str,
    scala: &str,
) -> Result<reqwest::Response> {
    client
        .post(format!("{url}/query-sync"))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({ "query": scala }))
        .send()
        .await
        .with_context(|| format!("joern --server unreachable at {url} (is it running?)"))
}

pub(crate) async fn read_joern_response(response: reqwest::Response) -> Result<String> {
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("joern --server query failed: HTTP {status}: {body}");
    }

    response
        .text()
        .await
        .context("could not read joern response body")
}
