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

fn one_location(loc: &LspLocation) -> Option<(String, u32, u32)> {
    let path = loc
        .uri
        .strip_prefix("file://")
        .unwrap_or(&loc.uri)
        .to_string();
    Some((
        path,
        loc.range.start.line + 1,
        loc.range.start.character + 1,
    ))
}
