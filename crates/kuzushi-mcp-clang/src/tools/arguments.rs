use anyhow::Result;
use kuzushi_mcp_common::doctor::which;
use kuzushi_mcp_common::AuthorizedDirectory;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;

use crate::clangd::ClangdClient;

use super::document::position_arg;
use super::health_handle::ClangdHandle;

const MAX_SOURCE_FILE_BYTES: usize = 8 * 1024 * 1024;

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
    let value = args
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("missing required integer argument: {name}"))?;
    u32::try_from(value).map_err(|_| anyhow::anyhow!("argument {name} exceeds u32 range"))
}

pub(crate) struct FileRequest {
    pub(crate) repo: AuthorizedDirectory,
    pub(crate) file: PathBuf,
    pub(crate) source_text: String,
}

impl FileRequest {
    pub(crate) fn from_args(args: &Value, handle: &ClangdHandle) -> Result<Self> {
        let repo = handle
            .read_capability
            .authorize_directory(std::path::Path::new(require_str(args, "repoPath")?))?;
        let opened = repo.open_file(
            std::path::Path::new(require_str(args, "file")?),
            MAX_SOURCE_FILE_BYTES,
        )?;
        let file = opened.path().to_path_buf();
        let source_text = opened.read_utf8()?;
        Ok(Self {
            repo,
            file,
            source_text,
        })
    }

    pub(crate) async fn client(&self, handle: &ClangdHandle) -> Result<Arc<ClangdClient>> {
        handle.for_repo(&self.repo).await
    }

    pub(crate) fn text_document(&self) -> Result<Value> {
        Ok(json!({ "textDocument": { "uri": crate::clangd::file_uri(&self.file)? } }))
    }
}

pub(crate) struct PositionRequest {
    pub(crate) file: FileRequest,
    pub(crate) line: u32,
    pub(crate) column: u32,
}

impl PositionRequest {
    pub(crate) fn from_args(args: &Value, handle: &ClangdHandle) -> Result<Self> {
        let file = FileRequest::from_args(args, handle)?;
        let line = require_u32(args, "line")?;
        let column = require_u32(args, "column")?;
        Ok(Self { file, line, column })
    }

    pub(crate) fn from_args_with_default_column(
        args: &Value,
        default_column: u32,
        handle: &ClangdHandle,
    ) -> Result<Self> {
        let file = FileRequest::from_args(args, handle)?;
        let line = require_u32(args, "line")?;
        let column = optional_u32(args, "column").unwrap_or(default_column);
        Ok(Self { file, line, column })
    }

    pub(crate) async fn client(&self, handle: &ClangdHandle) -> Result<Arc<ClangdClient>> {
        self.file.client(handle).await
    }

    pub(crate) fn params(&self) -> Result<Value> {
        position_arg(&self.file.file, self.line, self.column)
    }
}

pub(crate) fn optional_u32(args: &Value, name: &str) -> Option<u32> {
    args.get(name)
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
}
