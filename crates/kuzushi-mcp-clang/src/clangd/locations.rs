use kuzushi_mcp_common::tool_uri::reported_path;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct LspLocation {
    pub(crate) uri: String,
    pub(crate) range: LspRange,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct LspRange {
    pub(crate) start: LspPosition,
    #[allow(dead_code)]
    pub(crate) end: LspPosition,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct LspPosition {
    pub(crate) line: u32,
    pub(crate) character: u32,
}

pub fn parse_locations(value: &Value) -> Vec<(String, u32, u32)> {
    if value.is_null() {
        return Vec::new();
    }
    if let Ok(single) = serde_json::from_value::<LspLocation>(value.clone()) {
        return one_location(&single).into_iter().collect();
    }
    if let Ok(many) = serde_json::from_value::<Vec<LspLocation>>(value.clone()) {
        return many.iter().filter_map(one_location).collect();
    }
    Vec::new()
}

/// LSP positions are zero-based and the agent reads one-based lines, so both
/// coordinates are shifted here. The `uri` is read rather than stripped:
/// clangd escapes every path byte outside the RFC 3986 unreserved set, exactly
/// as `file_uri` does for the URIs this client sends, so dropping the scheme
/// alone reported `/tmp/a%20b.c` for a file named `/tmp/a b.c`.
fn one_location(loc: &LspLocation) -> Option<(String, u32, u32)> {
    Some((
        reported_path(&loc.uri)?,
        loc.range.start.line + 1,
        loc.range.start.character + 1,
    ))
}
