use kuzushi_mcp_common::schema::Symbol;
use serde_json::Value;
use std::path::Path;

use crate::router::Backend;

pub(crate) struct BackendToolCall {
    pub(crate) tool: &'static str,
    pub(crate) args: Value,
}

pub(crate) fn definition_call(
    backend: Backend,
    symbol: &str,
    repo: &Path,
) -> Option<BackendToolCall> {
    match backend {
        Backend::Gtags => Some(BackendToolCall {
            tool: "gtags.definitions",
            args: serde_json::json!({ "symbol": symbol, "repoPath": repo }),
        }),
        Backend::Cpg => Some(BackendToolCall {
            tool: "cpg.definitions",
            args: serde_json::json!({ "fn": symbol }),
        }),
        Backend::Clang => None,
    }
}

pub(crate) fn references_call(
    backend: Backend,
    symbol: &str,
    repo: &Path,
) -> Option<BackendToolCall> {
    (backend == Backend::Gtags).then(|| BackendToolCall {
        tool: "gtags.references",
        args: serde_json::json!({ "symbol": symbol, "repoPath": repo }),
    })
}

pub(crate) fn callers_call(
    backend: Backend,
    symbol: &str,
    position: Option<&FilePosition>,
) -> Option<BackendToolCall> {
    match (backend, position) {
        (Backend::Clang, Some(pos)) => Some(clang_position_call("clang.callers", pos)),
        (Backend::Cpg, _) => Some(cpg_function_call("cpg.callers_of", symbol)),
        _ => None,
    }
}

pub(crate) fn callees_call(
    backend: Backend,
    symbol: &str,
    position: Option<&FilePosition>,
) -> Option<BackendToolCall> {
    match (backend, position) {
        (Backend::Cpg, _) => Some(cpg_function_call("cpg.callees_of", symbol)),
        (Backend::Clang, Some(pos)) => Some(clang_position_call("clang.callees", pos)),
        _ => None,
    }
}

pub(crate) fn clang_position_call(tool: &'static str, position: &FilePosition) -> BackendToolCall {
    BackendToolCall {
        tool,
        args: serde_json::json!({
            "repoPath": position.repo,
            "file": position.file,
            "line": position.line,
            "column": position.column,
        }),
    }
}

pub(crate) fn cpg_function_call(tool: &'static str, symbol: &str) -> BackendToolCall {
    BackendToolCall {
        tool,
        args: serde_json::json!({ "fn": symbol }),
    }
}

pub(crate) fn symbol_matches(value: &Value) -> Vec<Symbol> {
    value
        .get("matches")
        .cloned()
        .and_then(|matches| serde_json::from_value::<Vec<Symbol>>(matches).ok())
        .unwrap_or_default()
}

pub(crate) fn backend_failure_diagnostic(
    backend: Backend,
    operation: &str,
    symbol: &str,
    err: &anyhow::Error,
) -> String {
    format!(
        "{} backend failed for {operation}({symbol}): {err}",
        backend.binary_name()
    )
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FilePosition {
    pub repo: std::path::PathBuf,
    pub file: String,
    pub line: u32,
    pub column: u32,
}
