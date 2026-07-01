//! Auto-spawn `joern --server` under the MCP server's lifetime.
//!
//! `kuzushi-mcp-joern` is a thin HTTP wrapper around joern's REST mode.
//! Operator UX before this module: install joern, run
//! `joern --server` in a separate terminal, set `JOERN_SERVER_URL`, then
//! call kuzushi. Most agents never get past the "is one running?" wall.
//!
//! Behaviour now:
//!   1. If `JOERN_SERVER_URL` is already set and the URL responds to a
//!      cheap HTTP probe, we use it (operator-managed mode preserved).
//!   2. Otherwise on the first taint/query call we spawn
//!      `joern --server --server-port <free> [<cpg.bin>]` ourselves,
//!      poll the port until it accepts, and cache the URL for the rest
//!      of the MCP server's lifetime.
//!   3. On MCP server shutdown the spawned child is killed via the
//!      handle's `Drop` impl. There's no stray joern hanging around.
//!
//! The CPG to import is taken from `KUZUSHI_JOERN_CPG`; if unset the
//! server starts empty and the agent must call `joern.parse` first or
//! pass an explicit CPG via `joern.query`.

use anyhow::{Context, Result};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const SPAWN_READINESS_TIMEOUT_SECS: u64 = 180;
const SPAWN_PROBE_INTERVAL_MS: u64 = 500;

/// Owns the spawned `joern --server` child. Killed on Drop so the
/// process tree dies with the MCP server.
struct JoernServerHandle {
    child: Child,
    url: String,
}

impl Drop for JoernServerHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn server_lock() -> &'static Mutex<Option<JoernServerHandle>> {
    static LOCK: OnceLock<Mutex<Option<JoernServerHandle>>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(None))
}

/// Resolve a URL pointing at a working `joern --server`. Returns the
/// URL of either an operator-managed server (if `JOERN_SERVER_URL`
/// reaches one) or a kuzushi-spawned one (otherwise). Idempotent: the
/// spawned child is reused for the rest of the MCP server's lifetime.
pub async fn ensure_joern_server() -> Result<String> {
    if let Some(url) = reachable_operator_server().await {
        return Ok(url);
    }
    ensure_spawned_joern_server().await
}

async fn ensure_spawned_joern_server() -> Result<String> {
    let mut guard = server_lock().lock().await;
    cached_or_new_joern_server(&mut guard).await
}

async fn cached_or_new_joern_server(guard: &mut Option<JoernServerHandle>) -> Result<String> {
    if let Some(url) = reachable_cached_server(guard).await {
        return Ok(url);
    }
    spawn_and_cache_joern_server(guard).await
}

async fn spawn_and_cache_joern_server(guard: &mut Option<JoernServerHandle>) -> Result<String> {
    let (url, command) = joern_server_spawn_plan()?;
    let handle = spawn_joern_server(command, url)?;
    wait_for_spawned_server(handle, guard).await
}

async fn reachable_operator_server() -> Option<String> {
    let url = std::env::var("JOERN_SERVER_URL").ok()?;
    probe_reachable(&url).await.then_some(url)
}

async fn reachable_cached_server(guard: &mut Option<JoernServerHandle>) -> Option<String> {
    let url = guard.as_ref().map(|handle| handle.url.clone())?;
    if probe_reachable(&url).await {
        return Some(url);
    }
    guard.take();
    None
}

fn joern_server_spawn_plan() -> Result<(String, Command)> {
    let port = pick_free_port().context("could not pick a free TCP port for joern --server")?;
    joern_server_spawn_plan_for_port(port)
}

fn joern_server_spawn_plan_for_port(port: u16) -> Result<(String, Command)> {
    let url = format!("http://127.0.0.1:{port}");
    let mut command = Command::new(joern_launcher_path()?);
    command
        .arg("--server")
        .arg("--server-host")
        .arg("127.0.0.1")
        .arg("--server-port")
        .arg(port.to_string());
    attach_configured_cpg(&mut command)?;
    Ok((url, command))
}

fn attach_configured_cpg(command: &mut Command) -> Result<()> {
    if let Some(cpg) = std::env::var_os("KUZUSHI_JOERN_CPG") {
        let cpg_path = std::path::PathBuf::from(&cpg);
        if !cpg_path.is_file() {
            anyhow::bail!(
                "KUZUSHI_JOERN_CPG points at {} which does not exist; build with `joern-parse <repo> --output <repo>/.kuzushi/cpg.bin`",
                cpg_path.display()
            );
        }
        command.arg(cpg_path);
    }
    Ok(())
}

fn spawn_joern_server(mut command: Command, url: String) -> Result<JoernServerHandle> {
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("could not spawn `joern --server`")?;
    Ok(JoernServerHandle { child, url })
}

async fn wait_for_spawned_server(
    handle: JoernServerHandle,
    guard: &mut Option<JoernServerHandle>,
) -> Result<String> {
    let url = handle.url.clone();
    let deadline = Instant::now() + Duration::from_secs(SPAWN_READINESS_TIMEOUT_SECS);
    while Instant::now() < deadline {
        if probe_reachable(&url).await {
            *guard = Some(handle);
            // Override JOERN_SERVER_URL for downstream callers in this
            // process. Safe because env mutation is process-local.
            std::env::set_var("JOERN_SERVER_URL", &url);
            return Ok(url);
        }
        tokio::time::sleep(Duration::from_millis(SPAWN_PROBE_INTERVAL_MS)).await;
    }
    anyhow::bail!(
        "joern --server did not become ready on {url} within {SPAWN_READINESS_TIMEOUT_SECS}s; \
         check joern's logs (re-spawn with KUZUSHI_BRIDGE_VERBOSE=1 for diagnostics)"
    );
}

async fn probe_reachable(url: &str) -> bool {
    let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
    else {
        return false;
    };
    // joern's REST server replies to GET / with a 405 (no GET handler)
    // but the connection itself succeeds, which is what we care about.
    matches!(client.get(url).send().await, Ok(_))
}

fn pick_free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("could not bind ephemeral port")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

fn joern_launcher_path() -> Result<std::path::PathBuf> {
    crate::tools::availability::locate_joern_binary("joern").ok_or_else(|| {
        anyhow::anyhow!(
            "could not locate the joern launcher; install via https://docs.joern.io/installation \
             or set KUZUSHI_JOERN_BIN=<path-to-joern>"
        )
    })
}
