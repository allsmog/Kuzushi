use anyhow::Result;
use kuzushi_mcp_common::doctor::which;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;

use crate::clangd::ClangdClient;

use super::document::position_arg;
use super::health_handle::ClangdHandle;

pub(crate) fn ensure_clangd() -> Result<()> {
    if which("clangd").is_none() {
        anyhow::bail!(
            "BackendUnavailable: clangd not on PATH. Install LLVM (e.g. `apt install clangd` / `brew install llvm`)."
        );
    }
    Ok(())
}

pub(crate) fn require_str<'a>(args: &'a Value, name: &str) -> Result<&'a str> {
    args.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing required argument: {name}"))
}

pub(crate) fn require_u32(args: &Value, name: &str) -> Result<u32> {
    args.get(name)
        .and_then(Value::as_u64)
        .map(|n| n as u32)
        .ok_or_else(|| anyhow::anyhow!("missing required integer argument: {name}"))
}

pub(crate) struct FileRequest {
    pub(crate) repo: PathBuf,
    pub(crate) file: PathBuf,
}

impl FileRequest {
    pub(crate) fn from_args(args: &Value) -> Result<Self> {
        let repo = PathBuf::from(require_str(args, "repoPath")?);
        let file = repo.join(require_str(args, "file")?);
        Ok(Self { repo, file })
    }

    pub(crate) async fn client(&self, handle: &ClangdHandle) -> Result<Arc<ClangdClient>> {
        handle.for_repo(&self.repo).await
    }

    pub(crate) fn text_document(&self) -> Value {
        json!({ "textDocument": { "uri": format!("file://{}", self.file.display()) } })
    }
}

pub(crate) struct PositionRequest {
    pub(crate) file: FileRequest,
    pub(crate) line: u32,
    pub(crate) column: u32,
}

impl PositionRequest {
    pub(crate) fn from_args(args: &Value) -> Result<Self> {
        let file = FileRequest::from_args(args)?;
        let line = require_u32(args, "line")?;
        let column = require_u32(args, "column")?;
        Ok(Self { file, line, column })
    }

    pub(crate) fn from_args_with_default_column(args: &Value, default_column: u32) -> Result<Self> {
        let file = FileRequest::from_args(args)?;
        let line = require_u32(args, "line")?;
        let column = optional_u32(args, "column").unwrap_or(default_column);
        Ok(Self { file, line, column })
    }

    pub(crate) async fn client(&self, handle: &ClangdHandle) -> Result<Arc<ClangdClient>> {
        self.file.client(handle).await
    }

    pub(crate) fn params(&self) -> Value {
        position_arg(&self.file.file, self.line, self.column)
    }
}

pub(crate) fn optional_u32(args: &Value, name: &str) -> Option<u32> {
    args.get(name).and_then(Value::as_u64).map(|n| n as u32)
}
