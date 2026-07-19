use super::{codeql_revision, CODEQL_BUNDLE_CONFIG};
use crate::database_identity;
use anyhow::{Context, Result};
use kuzushi_mcp_common::{
    copy_bounded_bundle_with_durability, resolve_codeql_bundle_root, CopyDurability,
};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use tempfile::TempDir;
use tokio::sync::Mutex as AsyncMutex;

mod builder;
mod cancellation;
mod session_root;
#[cfg(test)]
mod tests;

use builder::{canonical_launcher, create_database_snapshot, create_execution_snapshot};
use cancellation::SnapshotCancellation;
use session_root::{default_snapshot_parent, SnapshotSessionRoot};

#[derive(Clone, Debug, PartialEq, Eq)]
struct SnapshotKey {
    launcher: PathBuf,
    revision: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DatabaseSnapshotKey {
    source: PathBuf,
    revision: String,
}

#[derive(Clone)]
pub(super) struct DatabaseExecutionSnapshot {
    pub(super) directory: PathBuf,
    pub(super) revision: String,
    cancellation: Arc<SnapshotCancellation>,
    _directory: Arc<TempDir>,
    _session: Arc<SnapshotSessionRoot>,
}

impl DatabaseExecutionSnapshot {
    pub(super) fn cancel(&self) {
        self.cancellation.cancel();
    }

    pub(super) async fn cancelled(&self) {
        self.cancellation.cancelled().await;
    }

    pub(super) fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    pub(super) fn temporary_directory(&self, prefix: &str) -> Result<TempDir> {
        tempfile::Builder::new()
            .prefix(prefix)
            .tempdir_in(self._session.path())
            .map_err(Into::into)
    }
}

#[derive(Clone)]
pub(super) struct CodeqlExecutionSnapshot {
    pub(super) launcher: PathBuf,
    pub(super) bundle_root: PathBuf,
    pub(super) revision: String,
    cancellation: Arc<SnapshotCancellation>,
    _directory: Arc<TempDir>,
    _session: Arc<SnapshotSessionRoot>,
}

impl CodeqlExecutionSnapshot {
    pub(super) fn cancel(&self) {
        self.cancellation.cancel();
    }

    pub(super) async fn cancelled(&self) {
        self.cancellation.cancelled().await;
    }

    pub(super) fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
}

pub(super) struct CodeqlSnapshotStore {
    current: Mutex<Option<(SnapshotKey, CodeqlExecutionSnapshot)>>,
    current_database: Mutex<Option<(DatabaseSnapshotKey, DatabaseExecutionSnapshot)>>,
    retired: Mutex<Option<Weak<TempDir>>>,
    retired_database: Mutex<Option<Weak<TempDir>>>,
    build_gate: AsyncMutex<()>,
    database_build_gate: AsyncMutex<()>,
    session: Arc<SnapshotSessionRoot>,
}

impl CodeqlSnapshotStore {
    pub(super) fn new() -> Result<Self> {
        Self::new_in(default_snapshot_parent()?)
    }

    fn new_in(parent: PathBuf) -> Result<Self> {
        Ok(Self {
            current: Mutex::new(None),
            current_database: Mutex::new(None),
            retired: Mutex::new(None),
            retired_database: Mutex::new(None),
            build_gate: AsyncMutex::new(()),
            database_build_gate: AsyncMutex::new(()),
            session: Arc::new(SnapshotSessionRoot::create(&parent)?),
        })
    }

    pub(super) async fn authenticated(
        &self,
        launcher: &Path,
        revision: &str,
    ) -> Result<CodeqlExecutionSnapshot> {
        let launcher = canonical_launcher(launcher)?;
        let key = SnapshotKey {
            launcher: launcher.clone(),
            revision: revision.to_string(),
        };
        if let Some(snapshot) = self.cached(&key)? {
            return Ok(snapshot);
        }
        let _build = self.build_gate.lock().await;
        if let Some(snapshot) = self.cached(&key)? {
            return Ok(snapshot);
        }
        self.build(launcher, Some(revision.to_string())).await
    }

    /// Copy and identify an uncached bundle in one source-tree pass.
    pub(super) async fn current(&self, launcher: &Path) -> Result<CodeqlExecutionSnapshot> {
        let launcher = canonical_launcher(launcher)?;
        if self.cached_launcher(&launcher)?.is_some() {
            let candidate = launcher.clone();
            let revision = tokio::task::spawn_blocking(move || codeql_revision(&candidate))
                .await
                .context("CodeQL identity worker stopped")??;
            return self.authenticated(&launcher, &revision).await;
        }
        let _build = self.build_gate.lock().await;
        if self.cached_launcher(&launcher)?.is_some() {
            drop(_build);
            let candidate = launcher.clone();
            let revision = tokio::task::spawn_blocking(move || codeql_revision(&candidate))
                .await
                .context("CodeQL identity worker stopped")??;
            return self.authenticated(&launcher, &revision).await;
        }
        self.build(launcher, None).await
    }

    pub(super) async fn database(
        &self,
        source: &Path,
        revision: &str,
    ) -> Result<DatabaseExecutionSnapshot> {
        let source = std::fs::canonicalize(source)?;
        let key = DatabaseSnapshotKey {
            source: source.clone(),
            revision: revision.to_string(),
        };
        if let Some(snapshot) = self.cached_database(&key)? {
            return Ok(snapshot);
        }
        let _build = self.database_build_gate.lock().await;
        if let Some(snapshot) = self.cached_database(&key)? {
            return Ok(snapshot);
        }
        ensure_retired_released(&self.retired_database, "database")?;
        let session = Arc::clone(&self.session);
        let build_source = source.clone();
        let expected = revision.to_string();
        let snapshot = tokio::task::spawn_blocking(move || {
            create_database_snapshot(session, &build_source, &expected)
        })
        .await
        .context("CodeQL database snapshot worker stopped")??;
        let key = DatabaseSnapshotKey {
            source,
            revision: snapshot.revision.clone(),
        };
        let mut current = self.lock_database()?;
        if let Some((_, replaced)) = current.replace((key, snapshot.clone())) {
            replaced.cancel();
            remember_retired(&self.retired_database, &replaced._directory)?;
        }
        Ok(snapshot)
    }

    pub(super) fn cancel_all(&self) {
        cancel_codeql_snapshot(&self.current);
        cancel_database_snapshot(&self.current_database);
    }

    fn cached(&self, key: &SnapshotKey) -> Result<Option<CodeqlExecutionSnapshot>> {
        let current = self.lock_current()?;
        Ok(current
            .as_ref()
            .filter(|(cached, snapshot)| cached == key && !snapshot.is_cancelled())
            .map(|(_, snapshot)| snapshot.clone()))
    }

    fn cached_launcher(&self, launcher: &Path) -> Result<Option<CodeqlExecutionSnapshot>> {
        let current = self.lock_current()?;
        Ok(current
            .as_ref()
            .filter(|(key, snapshot)| key.launcher == launcher && !snapshot.is_cancelled())
            .map(|(_, snapshot)| snapshot.clone()))
    }

    fn cached_database(
        &self,
        key: &DatabaseSnapshotKey,
    ) -> Result<Option<DatabaseExecutionSnapshot>> {
        let current = self.lock_database()?;
        Ok(current
            .as_ref()
            .filter(|(cached, snapshot)| cached == key && !snapshot.is_cancelled())
            .map(|(_, snapshot)| snapshot.clone()))
    }

    async fn build(
        &self,
        launcher: PathBuf,
        expected: Option<String>,
    ) -> Result<CodeqlExecutionSnapshot> {
        ensure_retired_released(&self.retired, "executable bundle")?;
        let session = Arc::clone(&self.session);
        let source = launcher.clone();
        let snapshot = tokio::task::spawn_blocking(move || {
            create_execution_snapshot(session, &source, expected.as_deref())
        })
        .await
        .context("CodeQL snapshot worker stopped")??;
        let key = SnapshotKey {
            launcher,
            revision: snapshot.revision.clone(),
        };
        let mut current = self.lock_current()?;
        if let Some((_, replaced)) = current.replace((key, snapshot.clone())) {
            replaced.cancel();
            remember_retired(&self.retired, &replaced._directory)?;
        }
        Ok(snapshot)
    }

    fn lock_current(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Option<(SnapshotKey, CodeqlExecutionSnapshot)>>> {
        self.current
            .lock()
            .map_err(|_| anyhow::anyhow!("CodeQL snapshot state is unavailable"))
    }

    fn lock_database(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Option<(DatabaseSnapshotKey, DatabaseExecutionSnapshot)>>>
    {
        self.current_database
            .lock()
            .map_err(|_| anyhow::anyhow!("CodeQL database snapshot state is unavailable"))
    }
}

fn cancel_codeql_snapshot(current: &Mutex<Option<(SnapshotKey, CodeqlExecutionSnapshot)>>) {
    let Ok(current) = current.lock() else {
        return;
    };
    if let Some((_, snapshot)) = current.as_ref() {
        snapshot.cancel();
    }
}

fn cancel_database_snapshot(
    current: &Mutex<Option<(DatabaseSnapshotKey, DatabaseExecutionSnapshot)>>,
) {
    let Ok(current) = current.lock() else {
        return;
    };
    if let Some((_, snapshot)) = current.as_ref() {
        snapshot.cancel();
    }
}

fn ensure_retired_released(retired: &Mutex<Option<Weak<TempDir>>>, label: &str) -> Result<()> {
    let mut retired = retired
        .lock()
        .map_err(|_| anyhow::anyhow!("CodeQL retired snapshot state is unavailable"))?;
    if retired
        .as_ref()
        .is_some_and(|snapshot| snapshot.upgrade().is_some())
    {
        anyhow::bail!("previous CodeQL {label} snapshot is still retiring; retry the operation");
    }
    *retired = None;
    Ok(())
}

fn remember_retired(retired: &Mutex<Option<Weak<TempDir>>>, snapshot: &Arc<TempDir>) -> Result<()> {
    let mut retired = retired
        .lock()
        .map_err(|_| anyhow::anyhow!("CodeQL retired snapshot state is unavailable"))?;
    *retired = Some(Arc::downgrade(snapshot));
    Ok(())
}
