use super::prelude::*;
use super::*;

pub(crate) fn summarize_surfaces(surfaces: &[AttackSurface]) -> AttackSurfaceSummary {
    let mut by_kind = BTreeMap::new();
    let mut by_file = BTreeMap::new();
    for surface in surfaces {
        *by_kind
            .entry(surface.kind.as_str().to_string())
            .or_insert(0) += 1;
        *by_file.entry(surface.path.clone()).or_insert(0) += 1;
    }
    AttackSurfaceSummary {
        total: surfaces.len(),
        by_kind,
        by_file,
    }
}

pub(crate) fn attack_surface_id(surface: &AttackSurface) -> String {
    let metadata = serde_json::to_string(&surface.metadata).unwrap_or_else(|_| "{}".to_string());
    let segments = [
        surface.kind.as_str(),
        &surface.path,
        &surface
            .line
            .map(|line| line.to_string())
            .unwrap_or_default(),
        &surface.language,
        surface.framework.as_deref().unwrap_or(""),
        &surface.title,
        &surface.evidence,
        surface.method.as_deref().unwrap_or(""),
        surface.route.as_deref().unwrap_or(""),
        surface.boundary.as_deref().unwrap_or(""),
        &metadata,
    ];
    let body = segments.join("\0");
    format!("AS-{}", &static_content_hash(&body)[..16])
}

pub(crate) fn language_from_path(path: &str) -> Option<&'static str> {
    let extension = Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())?
        .to_ascii_lowercase();
    match extension.as_str() {
        "js" | "jsx" | "mjs" | "cjs" => Some("JavaScript"),
        "ts" | "tsx" => Some("TypeScript"),
        "py" => Some("Python"),
        "go" => Some("Go"),
        "rs" => Some("Rust"),
        _ => None,
    }
}

pub(crate) fn trim_detail(line: &str) -> String {
    line.trim().split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(crate) fn line_contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

pub(crate) fn extract_quoted_after_marker_case_insensitive(
    line: &str,
    marker: &str,
) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let index = lower.find(marker)?;
    extract_first_quoted(&line[index + marker.len()..])
}

pub(crate) fn extract_first_quoted(value: &str) -> Option<String> {
    let mut chars = value.char_indices();
    while let Some((start, quote)) = chars.next() {
        if !matches!(quote, '"' | '\'' | '`') {
            continue;
        }
        for (offset, ch) in value[start + quote.len_utf8()..].char_indices() {
            if ch == quote {
                let end = start + quote.len_utf8() + offset;
                let candidate = &value[start + quote.len_utf8()..end];
                if !candidate.trim().is_empty() {
                    return Some(candidate.to_string());
                }
                return None;
            }
        }
    }
    None
}
