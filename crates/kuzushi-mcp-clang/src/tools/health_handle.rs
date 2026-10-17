use anyhow::Result;
use kuzushi_mcp_common::doctor::{BinaryProbe, HealthSummary};
use kuzushi_mcp_common::process::{run_bounded_process, ProcessLimits};
use kuzushi_mcp_common::read_only_sandbox::{
    read_only_command, resolve_regular_executable, sandbox_available,
};
use kuzushi_mcp_common::{AuthorizedDirectory, ReadRootCapability};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use crate::clangd::ClangdClient;
use kuzushi_mcp_common::compile_database::CompileDatabaseSnapshot;

pub(crate) const PROBES: &[(&str, &[&str])] =
    &[("clangd", &["--version"]), ("clang", &["--version"])];

pub async fn health_summary() -> HealthSummary {
    let sandbox_ready = sandbox_available().await;
    let mut probes = Vec::with_capacity(PROBES.len());
    let mut missing = Vec::new();
    for (binary, args) in PROBES {
        let (probe, runnable) = bounded_probe(binary, args, sandbox_ready).await;
        if !probe.found || !runnable {
            missing.push((*binary).to_string());
        }
        probes.push(probe);
    }
    if !sandbox_ready {
        missing.push("read-only-process-sandbox".to_string());
    }
    HealthSummary {
        ready: missing.is_empty(),
        probes,
        missing,
    }
}

async fn bounded_probe(binary: &str, args: &[&str], sandbox_ready: bool) -> (BinaryProbe, bool) {
    let Ok(path) = resolve_regular_executable(OsStr::new(binary)) else {
        return (missing_probe(binary), false);
    };
    if !sandbox_ready {
        return (present_probe(binary, path, None), false);
    }
    let result = run_probe_in_sandbox(&path, args).await;
    let version = result.as_ref().ok().and_then(first_version_line);
    (present_probe(binary, path, version), result.is_ok())
}

async fn run_probe_in_sandbox(path: &Path, args: &[&str]) -> Result<String> {
    let input_root = tempfile::Builder::new()
        .prefix("kuzushi-clang-health-")
        .tempdir()?;
    let capability = ReadRootCapability::new([input_root.path().to_path_buf()])?;
    let input = capability.authorize_directory(input_root.path())?;
    let mut sandboxed = read_only_command(path, args, input).await?;
    let output = run_bounded_process(
        sandboxed.command_mut()?,
        "clang health probe",
        health_probe_limits(),
    )
    .await?;
    anyhow::ensure!(
        output.status.success(),
        "clang health probe exited with {}",
        output.status
    );
    Ok(if output.stdout.is_empty() {
        output.stderr
    } else {
        output.stdout
    })
}

fn first_version_line(output: &String) -> Option<String> {
    output
        .lines()
        .find(|line| !line.is_empty())
        .map(str::to_owned)
}

fn missing_probe(binary: &str) -> BinaryProbe {
    BinaryProbe {
        binary: binary.to_string(),
        found: false,
        path: None,
        version: None,
    }
}

fn present_probe(binary: &str, path: PathBuf, version: Option<String>) -> BinaryProbe {
    BinaryProbe {
        binary: binary.to_string(),
        found: true,
        path: Some(path),
        version,
    }
}

fn health_probe_limits() -> ProcessLimits {
    ProcessLimits {
        timeout: Duration::from_secs(5),
        stdout_bytes: 64 * 1024,
        stderr_bytes: 64 * 1024,
    }
}

pub(crate) struct ClangdHandle {
    pub(crate) client: Mutex<Option<(PathBuf, Arc<ClangdClient>)>>,
    pub(crate) read_capability: ReadRootCapability,
}

impl ClangdHandle {
    pub(crate) fn new(read_capability: ReadRootCapability) -> Self {
        Self {
            client: Mutex::new(None),
            read_capability,
        }
    }

    pub(crate) async fn for_repo(
        &self,
        repo: &AuthorizedDirectory,
        database: Option<Arc<CompileDatabaseSnapshot>>,
    ) -> Result<Arc<ClangdClient>> {
        repo.verify_unchanged()?;
        let mut guard = self.client.lock().await;
        clangd_client_for_guard(&mut guard, repo, database).await
    }
}

#[cfg(test)]
impl Default for ClangdHandle {
    fn default() -> Self {
        let root = std::env::temp_dir();
        Self::new(ReadRootCapability::new([root]).expect("temp directory is a readable root"))
    }
}

pub(crate) async fn clangd_client_for_guard(
    guard: &mut Option<(PathBuf, Arc<ClangdClient>)>,
    repo: &AuthorizedDirectory,
    database: Option<Arc<CompileDatabaseSnapshot>>,
) -> Result<Arc<ClangdClient>> {
    let canonical = repo.path().to_path_buf();
    if let Some(client) = cached_clangd_client(guard, &canonical, database.as_deref()).await {
        return Ok(client);
    }
    let client = start_clangd_client(repo, database).await?;
    *guard = Some((canonical, client.clone()));
    Ok(client)
}

pub(crate) async fn cached_clangd_client(
    guard: &mut Option<(PathBuf, Arc<ClangdClient>)>,
    canonical: &Path,
    database: Option<&CompileDatabaseSnapshot>,
) -> Option<Arc<ClangdClient>> {
    let Some((existing, client)) = guard.as_ref() else {
        return None;
    };
    if same_clangd_configuration(existing, canonical, client, database) && client.is_running().await
    {
        return Some(client.clone());
    }
    let _ = client.shutdown().await;
    None
}

fn same_clangd_configuration(
    existing: &Path,
    requested: &Path,
    client: &ClangdClient,
    database: Option<&CompileDatabaseSnapshot>,
) -> bool {
    existing == requested && client.uses_database(database)
}

pub(crate) async fn start_clangd_client(
    repo: &AuthorizedDirectory,
    database: Option<Arc<CompileDatabaseSnapshot>>,
) -> Result<Arc<ClangdClient>> {
    let canonical = repo.path();
    let client = Arc::new(ClangdClient::spawn(repo.try_clone()?, database).await?);
    client.initialize(canonical).await?;
    Ok(client)
}
