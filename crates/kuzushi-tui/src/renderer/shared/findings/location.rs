//! Display-only abbreviation. Stored locations and full detail remain exact.
use crate::renderer::shared::text::{display_width, fit_path, take_columns};

pub(in crate::renderer) fn fit_location_label(value: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if display_width(value) <= width {
        return value.into();
    }
    let file_location = value.rsplit('/').next().unwrap_or(value);
    let prefix_width = width.saturating_sub(display_width(file_location).saturating_add(3));
    let prefix = location_prefix(value, prefix_width);
    if prefix.is_empty() {
        return fit_path(value, width);
    }
    format!("{prefix}/…/{file_location}")
}

fn location_prefix(value: &str, width: usize) -> String {
    let prefix = take_columns(value, width);
    if value[prefix.len()..].starts_with('/') {
        return prefix;
    }
    prefix
        .rsplit_once('/')
        .map_or(prefix.as_str(), |(complete, _)| complete)
        .into()
}

#[cfg(test)]
mod tests;
