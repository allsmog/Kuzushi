use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use kuzushi_core::{
    attach_source, attachment_store_path, detach_source, export_workspace_findings,
    is_supported_attachment_module, known_artifacts, list_attachments, reparse_source,
    FindingListFilter, FindingStore, WorkspaceTarget, SUPPORTED_ATTACHMENT_MODULES,
};

use super::{ContextSnapshotView, KnowledgeBaseView, ShellApp, ShellView, WorkspaceView};

impl ShellApp {
    pub(super) fn show_workspace_status(&mut self) {
        self.workspace_view = self.build_workspace_view(None);
        self.shell_view = ShellView::Workspace;
        self.focused_module = Some("workspace".to_string());
        self.log("workspace", self.workspace_view.status.clone());
    }

    pub(super) fn export_workspace_findings(&mut self, output: &PathBuf) {
        let workspace = match self.explicit_workspace() {
            Ok(workspace) => workspace,
            Err(error) => {
                self.workspace_view = self.build_workspace_view(None);
                self.shell_view = ShellView::Workspace;
                self.log("error", error.to_string());
                return;
            }
        };
        let output = if output.is_absolute() {
            output.clone()
        } else {
            workspace.root().join(output)
        };

        match export_workspace_findings(&workspace, &output, None) {
            Ok(report) => {
                self.workspace_view = self.build_workspace_view(Some(report.output_path.clone()));
                self.shell_view = ShellView::Workspace;
                self.focused_module = Some("workspace".to_string());
                self.log(
                    "export",
                    format!(
                        "wrote {} finding(s) to {} ({})",
                        report.count,
                        report.output_path.display(),
                        report.format.as_str()
                    ),
                );
            }
            Err(error) => {
                self.workspace_view = self.build_workspace_view(None);
                self.shell_view = ShellView::Workspace;
                self.log(
                    "error",
                    format!("{error}. Next: workspace export findings <path>.json"),
                );
            }
        }
    }

    pub(super) fn build_workspace_view(&self, last_export: Option<PathBuf>) -> WorkspaceView {
        let Some(target) = self.target.clone() else {
            return WorkspaceView {
                root: None,
                state_dir: None,
                findings_db: None,
                findings_count: None,
                last_export,
                status: "no active workspace. Next: scan <target> or start shell with --target ."
                    .to_string(),
            };
        };

        match WorkspaceTarget::new(&target) {
            Ok(workspace) => {
                let findings_db = workspace.findings_db_path();
                let findings_count = if findings_db.exists() {
                    FindingStore::open(&findings_db)
                        .and_then(|store| store.list_findings(FindingListFilter::MAX_LIMIT))
                        .map(|findings| findings.len())
                        .ok()
                } else {
                    Some(0)
                };
                let count_label = findings_count
                    .map(|count| count.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                WorkspaceView {
                    root: Some(workspace.root().to_path_buf()),
                    state_dir: Some(workspace.state_dir()),
                    findings_db: Some(findings_db),
                    findings_count,
                    last_export,
                    status: format!(
                        "workspace ready; {count_label} finding(s). Next: workspace export findings <path>.json"
                    ),
                }
            }
            Err(error) => WorkspaceView {
                root: None,
                state_dir: None,
                findings_db: None,
                findings_count: None,
                last_export,
                status: format!("{error}. Next: scan <target>"),
            },
        }
    }

    pub(super) fn show_context_status(&mut self) {
        match self.refresh_context_view() {
            Ok(()) => {
                self.focused_module = Some("context".to_string());
                self.shell_view = ShellView::Context;
                self.log("context", self.context_view.status.clone());
            }
            Err(error) => self.log("error", error.to_string()),
        }
    }

    pub(super) fn build_context_snapshot(&mut self, scope: Option<&str>) {
        let workspace = match self.current_workspace() {
            Ok(workspace) => workspace,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        self.target = Some(workspace.root().to_path_buf());

        let mut input = serde_json::Map::new();
        if let Some(scope) = scope {
            input.insert("scope".to_string(), serde_json::json!(scope));
        }
        let input = match self.registry.prepare_tool_input(
            "context:build",
            serde_json::Value::Object(input),
            Some(&self.option_store),
        ) {
            Ok(input) => input,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        self.focused_module = Some("context".to_string());
        self.shell_view = ShellView::Context;
        self.start_background_tool(
            "context:build".to_string(),
            input,
            workspace,
            "indexing repository context",
            None,
        );
    }

    pub(super) fn regen_context_slice(&mut self, slice: &str) {
        match slice {
            "all" | "repo" | "app-model" => self.build_context_snapshot(Some(slice)),
            "enrichment" => self.log(
                "error",
                "context regen enrichment is not supported by the native Rust context builder yet. Next: context build",
            ),
            other => self.log(
                "error",
                format!(
                    "unknown context slice {other:?}. Valid slices: all, repo, app-model. Next: context regen repo"
                ),
            ),
        }
    }

    pub(super) fn refresh_context_view(&mut self) -> Result<()> {
        let workspace = self.current_workspace()?;
        let snapshot_path = workspace.root().join(".kuzushi/context-snapshot.json");
        self.context_view = load_context_snapshot_view(snapshot_path)?;
        Ok(())
    }

    pub(super) fn show_kb(&mut self, module: Option<String>) {
        let module_id = match self.resolve_kb_module(module) {
            Ok(module_id) => module_id,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        match self.refresh_kb_view(&module_id) {
            Ok(()) => {
                self.focused_module = Some(module_id.clone());
                self.shell_view = ShellView::KnowledgeBase;
                self.kb_scroll = 0;
                self.log(
                    "kb",
                    format!(
                        "{} attachment(s) for {module_id}. Next: attach <path-or-url>",
                        self.kb_view
                            .attachments
                            .iter()
                            .filter(|record| record.module_id == module_id)
                            .count()
                    ),
                );
            }
            Err(error) => self.log("error", error.to_string()),
        }
    }

    pub(super) fn attach_kb_source(&mut self, source: &str) {
        let module_id = match self.resolve_kb_module(None) {
            Ok(module_id) => module_id,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        let workspace = match self.current_workspace() {
            Ok(workspace) => workspace,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        match attach_source(&workspace, &module_id, source) {
            Ok(record) => {
                let _ = self.refresh_kb_view(&module_id);
                self.focused_module = Some(module_id);
                self.shell_view = ShellView::KnowledgeBase;
                self.log(
                    "attach",
                    format!(
                        "{} {} ({})",
                        record.id,
                        record.source,
                        if record.metadata_only {
                            "metadata-only"
                        } else {
                            "local"
                        }
                    ),
                );
            }
            Err(error) => self.log("error", error.to_string()),
        }
    }

    pub(super) fn detach_kb_source(&mut self, id: &str) {
        let workspace = match self.current_workspace() {
            Ok(workspace) => workspace,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        match detach_source(&workspace, id) {
            Ok(record) => {
                let module_id = record.module_id.clone();
                let _ = self.refresh_kb_view(&module_id);
                self.focused_module = Some(module_id);
                self.shell_view = ShellView::KnowledgeBase;
                self.log("detach", format!("removed {} {}", record.id, record.source));
            }
            Err(error) => self.log("error", error.to_string()),
        }
    }

    pub(super) fn reparse_kb_source(&mut self, id: &str) {
        let workspace = match self.current_workspace() {
            Ok(workspace) => workspace,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        match reparse_source(&workspace, id) {
            Ok(record) => {
                let module_id = record.module_id.clone();
                let _ = self.refresh_kb_view(&module_id);
                self.focused_module = Some(module_id);
                self.shell_view = ShellView::KnowledgeBase;
                self.log("reparse", format!("{} {}", record.id, record.status));
            }
            Err(error) => self.log("error", error.to_string()),
        }
    }

    pub(super) fn refresh_kb_view(&mut self, module_id: &str) -> Result<()> {
        let workspace = self.current_workspace()?;
        let attachments = list_attachments(&workspace)?;
        let artifacts = known_artifacts(&workspace, module_id)?;
        self.kb_view = KnowledgeBaseView {
            module_id: module_id.to_string(),
            store_path: Some(attachment_store_path(&workspace)),
            attachments,
            artifacts,
        };
        Ok(())
    }

    pub(super) fn resolve_kb_module(&self, requested: Option<String>) -> Result<String> {
        if let Some(module_id) = requested {
            let module_id = normalize_kb_module_id(&module_id);
            if is_supported_attachment_module(&module_id) {
                return Ok(module_id);
            }
            anyhow::bail!("{}", unknown_kb_module_message(&module_id));
        }

        if let Some(module_id) = self
            .focused_module
            .as_deref()
            .map(normalize_kb_module_id)
            .filter(|module_id| is_supported_attachment_module(module_id))
        {
            return Ok(module_id);
        }

        if is_supported_attachment_module(&self.kb_view.module_id) {
            return Ok(self.kb_view.module_id.clone());
        }

        Ok("context".to_string())
    }
}

pub(super) fn default_context_snapshot_view(snapshot_path: Option<PathBuf>) -> ContextSnapshotView {
    ContextSnapshotView {
        snapshot_path,
        exists: false,
        status: "missing. Next: context build".to_string(),
        target: None,
        discovery: None,
        files_indexed: None,
        total_files: None,
        languages: Vec::new(),
        frameworks: Vec::new(),
        generated_slices: Vec::new(),
        stale_slices: Vec::new(),
    }
}

pub(super) fn default_workspace_view(target: Option<&WorkspaceTarget>) -> WorkspaceView {
    match target {
        Some(workspace) => WorkspaceView {
            root: Some(workspace.root().to_path_buf()),
            state_dir: Some(workspace.state_dir()),
            findings_db: Some(workspace.findings_db_path()),
            findings_count: None,
            last_export: None,
            status: "workspace ready. Next: workspace status".to_string(),
        },
        None => WorkspaceView {
            root: None,
            state_dir: None,
            findings_db: None,
            findings_count: None,
            last_export: None,
            status: "no active workspace. Next: scan <target> or start shell with --target ."
                .to_string(),
        },
    }
}

fn load_context_snapshot_view(snapshot_path: PathBuf) -> Result<ContextSnapshotView> {
    if !snapshot_path.exists() {
        return Ok(default_context_snapshot_view(Some(snapshot_path)));
    }

    let body = fs::read_to_string(&snapshot_path)
        .with_context(|| format!("Could not read {}", snapshot_path.display()))?;
    let snapshot: serde_json::Value = serde_json::from_str(&body)
        .with_context(|| format!("Could not parse {}", snapshot_path.display()))?;
    let files_indexed = snapshot
        .get("filesIndexed")
        .and_then(serde_json::Value::as_u64);
    let total_files = snapshot
        .pointer("/fileIndex/totalFiles")
        .and_then(serde_json::Value::as_u64);
    let generated_slices = json_string_array(snapshot.get("generatedSlices"));
    let stale_slices = json_string_array(snapshot.get("staleSlices"));
    let languages = json_string_array(snapshot.pointer("/repoContext/languages"));
    let frameworks = json_string_array(snapshot.pointer("/repoContext/frameworks"));
    let target = snapshot
        .get("target")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string);
    let discovery = snapshot
        .get("discovery")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string);
    let status = format!(
        "snapshot present; {} indexed file(s). Next: context regen repo",
        files_indexed.or(total_files).unwrap_or(0)
    );

    Ok(ContextSnapshotView {
        snapshot_path: Some(snapshot_path),
        exists: true,
        status,
        target,
        discovery,
        files_indexed,
        total_files,
        languages,
        frameworks,
        generated_slices,
        stale_slices,
    })
}

fn json_string_array(value: Option<&serde_json::Value>) -> Vec<String> {
    value
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn normalize_kb_module_id(raw_id: &str) -> String {
    match raw_id.trim().to_ascii_lowercase().as_str() {
        "tm" | "threat" | "threats" => "threat-model".to_string(),
        "carlini" | "threat-hunt" => "carlini-threat-hunt".to_string(),
        "xray" | "x_ray" => "x-ray".to_string(),
        other => other.to_string(),
    }
}

fn unknown_kb_module_message(module_id: &str) -> String {
    format!(
        "unknown KB module {module_id:?}. Supported KB modules: {}. Next: kb context",
        SUPPORTED_ATTACHMENT_MODULES.join(", ")
    )
}
