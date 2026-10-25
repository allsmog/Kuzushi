//! Bounded, invocation-local source snapshots for optional duplicate confirmation.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Component, Path};

pub(super) struct SourceInputs<'a> {
    root: &'a Path,
    maximum: usize,
    remaining: usize,
    files: BTreeMap<String, SourceFile>,
}

struct SourceFile {
    text: Option<String>,
    receipt: Value,
}

impl<'a> SourceInputs<'a> {
    pub(super) fn new(root: &'a Path, maximum: usize) -> Self {
        Self {
            root,
            maximum,
            remaining: maximum,
            files: BTreeMap::new(),
        }
    }

    pub(super) fn text(&mut self, path: &str) -> Result<&str> {
        if !self.files.contains_key(path) {
            let file = self.read(path);
            self.files.insert(path.to_string(), file);
        }
        self.files[path]
            .text
            .as_deref()
            .context("confirmation source unavailable within maxConfirmationBytes")
    }

    pub(super) fn receipt(&self) -> Value {
        json!({"schemaVersion":1,"basis":"current_workspace_files",
            "maxConfirmationBytes":self.maximum,"reservedBytes":self.maximum-self.remaining,
            "files":self.files.values().map(|file| &file.receipt).collect::<Vec<_>>(),
            "limitations":"Current files may differ from historical finding source. Failed reads retain their allowance with unknown bytes. A bounded read may probe one extra byte; this is not a wall-clock IO deadline."})
    }

    fn read(&mut self, path: &str) -> SourceFile {
        let relative = Path::new(path);
        if path.is_empty()
            || relative.is_absolute()
            || relative
                .components()
                .any(|p| matches!(p, Component::ParentDir))
        {
            return unavailable(path, 0, "invalid relative source path");
        }
        if self.remaining == 0 {
            return unavailable(path, 0, "maxConfirmationBytes exhausted");
        }
        self.read_reserved(path)
    }

    fn read_reserved(&mut self, path: &str) -> SourceFile {
        let reserved = std::mem::take(&mut self.remaining);
        let bytes = match crate::bounded_file::read_regular_bytes_within(
            self.root,
            Path::new(path),
            reserved,
        ) {
            Ok(bytes) => bytes,
            Err(error) => return unavailable(path, reserved, &error.to_string()),
        };
        self.remaining = reserved.saturating_sub(bytes.len());
        let digest = crate::worker_protocol::sha256_digest(&bytes).0;
        let length = bytes.len();
        let text = source_text(bytes);
        SourceFile {
            receipt: json!({"path":path,"state":if text.is_some(){"available"}else{"unavailable"},
            "reservedBytes":length,"readBytes":length,"sha256":digest,
            "note":if text.is_some(){"complete bounded UTF-8 file"}else{"not source-like UTF-8 text"}}),
            text,
        }
    }
}

fn source_text(bytes: Vec<u8>) -> Option<String> {
    if bytes.contains(&0) {
        return None;
    }
    String::from_utf8(bytes).ok()
}

fn unavailable(path: &str, reserved: usize, note: &str) -> SourceFile {
    SourceFile {
        text: None,
        receipt: json!({"path":path,"state":"unavailable",
        "reservedBytes":reserved,"readBytes":if reserved==0 {json!(0)}else{Value::Null},"note":note}),
    }
}

#[cfg(test)]
mod tests;
