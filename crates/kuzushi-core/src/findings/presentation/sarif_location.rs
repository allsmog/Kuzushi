//! SARIF 2.1.0 location policy, shared by every Kuzushi SARIF emitter.
//!
//! `workspace:export-findings` and `report:sarif` both project a finding's
//! reported path and line range into `result.locations[].physicalLocation`.
//! Each carried its own copy of that projection and the copies drifted: the
//! `report:sarif` one interpolated the raw path straight into `uri` and read
//! "no line reported" as line 1. Both documents are handed to CI gates and to
//! GitHub code scanning, which resolve a location by exactly these two fields,
//! so the policy lives here once rather than once per emitter.

use anyhow::Result;
use serde_json::{json, Value};
use std::path::Path;

/// The `originalUriBaseIds` key a workspace-relative SARIF location resolves
/// against. An emitter that returns `uriBaseId` from
/// [`sarif_artifact_location`] must declare this base on its run.
pub(crate) const WORKSPACE_ROOT_BASE_ID: &str = "WORKSPACE_ROOT";

/// SARIF 2.1.0 §3.4.4 forbids pairing `uriBaseId` with a `uri` that is already
/// absolute. Findings may be anchored to hierarchical URLs, opaque URI
/// identifiers, or absolute filesystem paths; all three must stay independent
/// of `WORKSPACE_ROOT`.
pub(crate) fn sarif_artifact_location(file: &str) -> Value {
    if has_uri_scheme(file) {
        return json!({ "uri": file });
    }
    if let Some(uri) = absolute_file_uri(file) {
        return json!({ "uri": uri });
    }
    json!({ "uri": relative_uri_reference(file), "uriBaseId": WORKSPACE_ROOT_BASE_ID })
}

/// `start_line == 0` means the detector reported no line. Omitting the region
/// keeps the location at artifact granularity instead of asserting line 1.
/// HAR and Burp imports build every `http-request` finding with line 0 against
/// a URL, so forging a line here would put a reviewed finding at line 1 of a
/// URL in the document a CI gate reads.
pub(crate) fn sarif_region(start_line: u32, end_line: Option<u32>) -> Option<Value> {
    if start_line == 0 {
        return None;
    }
    let mut region = json!({ "startLine": start_line });
    if let Some(end_line) = end_line {
        region["endLine"] = json!(end_line.max(start_line));
    }
    Some(region)
}

/// The run's `originalUriBaseIds`, naming the root that every relative location
/// resolves against.
pub(crate) fn sarif_original_uri_base_ids(root: &Path) -> Result<Value> {
    let mut base_ids = serde_json::Map::new();
    base_ids.insert(
        WORKSPACE_ROOT_BASE_ID.to_string(),
        json!({ "uri": sarif_root_uri(root)? }),
    );
    Ok(Value::Object(base_ids))
}

/// The `file:` URI every relative result location resolves against. SARIF
/// 2.1.0 §3.4.3 requires a real URI here, so the root has to be percent-encoded
/// and `/`-separated, and on Windows the drive letter belongs in the path
/// rather than the authority. `url` is the same encoder the clangd MCP client
/// already uses for its own file URIs; interpolating `Path::display()` produced
/// a valid URI only when the root happened to contain no character needing an
/// escape.
pub(crate) fn sarif_root_uri(root: &Path) -> Result<String> {
    url::Url::from_directory_path(root)
        .map(String::from)
        .map_err(|_| {
            anyhow::anyhow!(
                "Could not encode a file URI for the workspace root: {}",
                root.display()
            )
        })
}

/// The `file:` URI for a location the detector reported as an absolute
/// filesystem path, or `None` when the path is workspace-relative.
///
/// A `uri` carrying `uriBaseId` is resolved against that base, so binding an
/// absolute path to `WORKSPACE_ROOT` renames the finding: `C:\src\app.rs`
/// becomes `<workspace root>/C%3A%5Csrc%5Capp.rs`, a file that exists nowhere.
/// Absolute paths do reach these exports — `normalize_reported_file_path` keeps
/// a model-reported path verbatim when it does not sit under the target root, as
/// happens for a vendored dependency read from a system prefix or for a macOS
/// `/private/var` path whose target was resolved as `/var`. Naming such a
/// location honestly outside the workspace beats re-anchoring it inside one.
///
/// A leading `\\` is deliberately *not* read as a UNC share. `\` is an ordinary
/// filename byte on Unix and `secret_relative_path` builds its path straight
/// from `Path::display()`, so a repository file named `\\build01\share.rs` would
/// be re-pointed at a network host that does not exist. That path keeps
/// resolving against `WORKSPACE_ROOT` with its bytes escaped, for the same
/// reason `relative_uri_reference` escapes `\` rather than splitting on it: the
/// escape is reversible, a wrong reading is not. A Windows drive prefix carries
/// no such ambiguity, which is why it does get an absolute reading here.
pub(crate) fn absolute_file_uri(file: &str) -> Option<String> {
    if is_windows_drive_absolute(file) {
        return Some(format!(
            "file:///{}",
            absolute_uri_path(&file.replace('\\', "/"))
        ));
    }
    file.starts_with('/')
        .then(|| format!("file://{}", absolute_uri_path(file)))
}

/// Percent-encode an already-`/`-separated absolute path. `:` stays literal
/// here, unlike in `relative_uri_reference`: it is a legal path character once
/// the reference is absolute, and keeping it preserves the conventional
/// `file:///C:/…` drive form that consumers map back to a Windows path.
fn absolute_uri_path(path: &str) -> String {
    path.bytes()
        .map(|byte| {
            if byte == b':' {
                ":".to_string()
            } else {
                encoded_path_byte(byte)
            }
        })
        .collect()
}

/// Turn a workspace-relative path into the URI reference SARIF 2.1.0 §3.4.2
/// asks for: `/` stays the separator and every other byte outside the RFC 3986
/// unreserved set is percent-encoded. A repository file named
/// `docs/My Notes.md` is otherwise emitted as a `uri` containing a space, which
/// consumers reject. Non-ASCII names encode per UTF-8 byte, so the escaped form
/// still names the same file, and `:` is escaped so a first segment like `C:`
/// cannot be misread as a scheme.
///
/// `\` is escaped rather than read as a separator. On Unix it is an ordinary
/// filename character that detectors preserve verbatim — `secret_relative_path`
/// builds its path straight from `Path::display()` — so splitting on it would
/// point a consumer at a file that does not exist. Producers that do run on
/// Windows paths (`incremental_index`, `inspect_entrypoints`) already normalize
/// to `/` where the path is produced, so nothing is lost by declining to guess
/// here. `%5C` is reversible; a wrong split is not.
pub(crate) fn relative_uri_reference(file: &str) -> String {
    file.bytes().map(encoded_path_byte).collect()
}

fn encoded_path_byte(byte: u8) -> String {
    if byte == b'/' || byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
        return char::from(byte).to_string();
    }
    format!("%{byte:02X}")
}

pub(crate) fn has_uri_scheme(file: &str) -> bool {
    if is_windows_drive_path(file) {
        return false;
    }
    let Some((scheme, _)) = file.split_once(':') else {
        return false;
    };
    let mut chars = scheme.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
}

/// A drive letter is never a URI scheme. This also accepts the drive-*relative*
/// `C:dir\file` form, which stays workspace-bound: it names a file relative to
/// that drive's working directory, so there is no absolute URI to emit for it.
fn is_windows_drive_path(file: &str) -> bool {
    is_windows_drive_absolute(file) || (has_drive_prefix(file) && file[2..].contains('\\'))
}

fn is_windows_drive_absolute(file: &str) -> bool {
    has_drive_prefix(file) && matches!(file.as_bytes()[2], b'/' | b'\\')
}

fn has_drive_prefix(file: &str) -> bool {
    let bytes = file.as_bytes();
    bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

#[cfg(test)]
#[path = "tests/sarif_location.rs"]
mod tests;
