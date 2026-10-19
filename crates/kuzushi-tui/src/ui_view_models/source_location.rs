//! Human-readable locations, kept separate from raw finding and export paths.
use kuzushi_core::Finding;
use std::path::Path;

pub(super) fn relative_source_path(path: &str, base: Option<&str>) -> String {
    let Some(base) = base else {
        return path.into();
    };
    match Path::new(path).strip_prefix(base) {
        Ok(relative) if !relative.as_os_str().is_empty() => relative.to_string_lossy().into_owned(),
        _ => path.into(),
    }
}

pub(super) fn source_path_label(path: &str, base: Option<&str>) -> String {
    let relative = relative_source_path(path, base);
    if relative.chars().any(path_needs_quotes) {
        return serde_json::Value::String(relative).to_string();
    }
    relative
}

fn path_needs_quotes(character: char) -> bool {
    character.is_whitespace() || character.is_control() || matches!(character, ':' | '\\' | '"')
}

pub(super) fn source_location_label(
    path: &str,
    line: Option<u64>,
    end: Option<u64>,
    base: Option<&str>,
) -> String {
    let path = source_path_label(path, base);
    match line {
        Some(line) => format!("{path}:{}", line_label(line, end)),
        None => path,
    }
}

fn line_label(line: u64, end: Option<u64>) -> String {
    match end {
        Some(end) if end > line => format!("{line}-{end}"),
        _ => line.to_string(),
    }
}

pub(super) fn finding_location_label(finding: &Finding, base: Option<&str>) -> String {
    source_location_label(
        &finding.file_path,
        Some(u64::from(finding.start_line)),
        finding.end_line.map(u64::from),
        base,
    )
}

#[cfg(test)]
mod tests;
