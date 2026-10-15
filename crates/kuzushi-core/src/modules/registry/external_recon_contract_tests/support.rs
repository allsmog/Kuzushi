use crate::{ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::{json, Value};
use std::path::PathBuf;

pub(super) struct Fixture {
    _root: tempfile::TempDir,
    pub workspace: WorkspaceTarget,
    config: V2Config,
    pub cancel: crate::scan::ScanCancellation,
}
impl Fixture {
    pub fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("hello.txt"),
            "Owned inert greeting. Never executed.\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        Self {
            _root: root,
            workspace,
            config: Default::default(),
            cancel: Default::default(),
        }
    }
    pub fn context(&self) -> ToolExecutionContext<'_> {
        ToolExecutionContext {
            config: &self.config,
            workspace: Some(&self.workspace),
            findings_store: None,
            trace: None,
            cancellation: Some(&self.cancel),
            authorization: Default::default(),
        }
    }
    #[cfg(unix)]
    pub fn script(&self, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = self.workspace.root().join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
    pub fn dispatch(&self, name: &str, input: Value, authorize: bool) -> anyhow::Result<Value> {
        let registry = ModuleRegistry::with_v2_builtins();
        let ctx = self.context();
        let mut prepared = registry.prepare_dispatch_input(name, input, &ctx, None)?;
        if authorize {
            prepared = prepared.authorize_explicit_headless();
        }
        registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None)
    }
}
pub(super) fn input(name: &str, binary: PathBuf) -> Value {
    match name {
        "recon:nmap" => json!({"target":"192.0.2.10","ports":"80","binary":binary}),
        "recon:subdomain" => json!({"domain":"owned.invalid","source":"crtsh","binary":binary}),
        _ => json!({"target":"http://owned.invalid/","binary":binary}),
    }
}
