use anyhow::Result;
use serde_json::{json, Value};

use crate::clangd::file_uri;
use crate::clangd::ClangdClient;

pub(crate) async fn open_document(
    client: &ClangdClient,
    file: &std::path::Path,
    text: &str,
) -> Result<()> {
    let uri = file_uri(file)?;
    client
        .notify(
            "textDocument/didOpen",
            json!({
                "textDocument": {
                    "uri": uri,
                    "languageId": clang_language_id(file),
                    "version": 1,
                    "text": text,
                }
            }),
        )
        .await
}

pub(crate) fn clang_language_id(file: &std::path::Path) -> &'static str {
    match file.extension().and_then(|extension| extension.to_str()) {
        Some("c" | "h") => "c",
        Some("cc" | "cpp" | "cxx" | "hpp" | "hxx" | "hh") => "cpp",
        _ => "cpp",
    }
}

pub(crate) fn position_arg(file: &std::path::Path, line: u32, column: u32) -> Result<Value> {
    Ok(json!({
        "textDocument": { "uri": file_uri(file)? },
        "position": { "line": line.saturating_sub(1), "character": column.saturating_sub(1) }
    }))
}
