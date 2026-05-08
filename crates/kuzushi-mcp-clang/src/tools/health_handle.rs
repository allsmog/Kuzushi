use anyhow::Result;
use kuzushi_mcp_common::doctor::{probe_all, HealthSummary};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::clangd::ClangdClient;

pub(crate) const PROBES: &[(&str, &[&str])] =
    &[("clangd", &["--version"]), ("clang", &["--version"])];

pub async fn health_summary() -> HealthSummary {
    probe_all(PROBES).await
}

#[derive(Default)]
pub(crate) struct ClangdHandle(pub(crate) Mutex<Option<(PathBuf, Arc<ClangdClient>)>>);

impl ClangdHandle {
    pub(crate) async fn for_repo(&self, repo: &Path) -> Result<Arc<ClangdClient>> {
        let canonical = canonical_repo(repo)?;
        let mut guard = self.0.lock().await;
        clangd_client_for_guard(&mut guard, canonical).await
    }
}

pub(crate) fn canonical_repo(repo: &Path) -> Result<PathBuf> {
    Ok(std::fs::canonicalize(repo)?)
}

pub(crate) async fn clangd_client_for_guard(
    guard: &mut Option<(PathBuf, Arc<ClangdClient>)>,
    canonical: PathBuf,
) -> Result<Arc<ClangdClient>> {
    if let Some(client) = cached_clangd_client(guard, &canonical).await {
        return Ok(client);
    }
    let client = start_clangd_client(&canonical).await?;
    *guard = Some((canonical, client.clone()));
    Ok(client)
}

pub(crate) async fn cached_clangd_client(
    guard: &mut Option<(PathBuf, Arc<ClangdClient>)>,
    canonical: &Path,
) -> Option<Arc<ClangdClient>> {
    let Some((existing, client)) = guard.as_ref() else {
        return None;
    };
    if existing == canonical {
        return Some(client.clone());
    }
    let _ = client.shutdown().await;
    None
}

pub(crate) async fn start_clangd_client(canonical: &Path) -> Result<Arc<ClangdClient>> {
    let client = Arc::new(ClangdClient::spawn(canonical).await?);
    client.initialize(canonical).await?;
    Ok(client)
}
