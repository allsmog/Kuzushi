//! M2 §2.2 shared scaffolding for the recon import adapters. Each
//! importer (amass/httpx/nuclei/nmap-xml) needs the same wiring around
//! file read, scope load, workspace registration, and `ReconReport`
//! construction. Centralising that scaffolding keeps the per-adapter
//! files short and lets the CRAP-risk gate hold.

use super::*;
use crate::workspace::{load_program_scope, ProgramScope, WorkspaceTarget};

/// Per-call recon-import state passed to every per-entry persistence
/// helper. Carries the store, workspace id, optional scope, and the
/// running output vectors so the call sites stay small.
pub(crate) struct ReconImportContext<'a> {
    pub(crate) store: ReconWorkspaceStore,
    pub(crate) workspace: &'a WorkspaceTarget,
    pub(crate) workspace_id: String,
    pub(crate) scope: Option<ProgramScope>,
    pub(crate) hosts: Vec<ReconHost>,
    pub(crate) services: Vec<ReconService>,
    pub(crate) notes: Vec<ReconNote>,
    pub(crate) skipped_out_of_scope: usize,
}

impl<'a> ReconImportContext<'a> {
    pub(crate) fn open(workspace: &'a WorkspaceTarget) -> Result<Self> {
        let scope = load_program_scope(workspace).context("Could not load scope.toml")?;
        let mut store = ReconWorkspaceStore::open(workspace)?;
        let workspace_id = store.ensure_default_workspace(workspace.root())?;
        Ok(Self {
            store,
            workspace,
            workspace_id,
            scope,
            hosts: Vec::new(),
            services: Vec::new(),
            notes: Vec::new(),
            skipped_out_of_scope: 0,
        })
    }

    /// `true` when the host is OK to persist. `None` scope returns
    /// `true`; explicit `OutOfScope` increments the skip counter.
    pub(crate) fn admit_host(&mut self, host: &str) -> bool {
        let Some(scope) = self.scope.as_ref() else {
            return true;
        };
        if scope.host_allowed(host) {
            return true;
        }
        self.skipped_out_of_scope += 1;
        false
    }

    pub(crate) fn into_report(self, tool: &str, target: String) -> Result<ReconReport> {
        let host_count = self.store.count_hosts()?;
        let service_count = self.store.count_services()?;
        Ok(ReconReport {
            tool: tool.to_string(),
            target,
            hosts: self.hosts,
            services: self.services,
            notes: self.notes,
            persisted: ReconPersisted {
                workspace_id: self.workspace_id,
                db: self.workspace.findings_db_path().display().to_string(),
                host_count,
                service_count,
            },
            subdomains: Vec::new(),
            fingerprint: BTreeMap::new(),
        })
    }
}

pub(crate) fn read_jsonl_path(input: &Value, message: &str) -> Result<(std::path::PathBuf, String)> {
    let path = required_path(input, "path", message)?;
    let body = crate::bounded_file::read_utf8_text(&path, 64 * 1024 * 1024)
        .with_context(|| format!("Could not read {}", path.display()))?;
    Ok((path, body))
}
