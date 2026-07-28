use super::*;

mod file_filters;
mod input_options;
mod json_fields;
mod output_contract;
mod threat_metrics;

#[cfg(test)]
pub(in crate::capabilities::carlini_threat_hunt) use crate::options::looks_like_prompt_path;
pub(in crate::capabilities::carlini_threat_hunt) use file_filters::{
    is_context_file, should_skip_path,
};
pub(in crate::capabilities::carlini_threat_hunt) use input_options::{
    bool_input, optional_string, read_usize, resolve_prompt_override,
};
pub(in crate::capabilities::carlini_threat_hunt) use json_fields::{
    object_string_array, object_string_value, read_object_string, read_object_string_array,
    unique_strings,
};
pub(in crate::capabilities::carlini_threat_hunt) use output_contract::{
    findings_schema, require_json_object,
};
pub(in crate::capabilities::carlini_threat_hunt) use threat_metrics::{
    carlini_severity, critical_count,
};

pub(in crate::capabilities::carlini_threat_hunt) fn build_actor_fingerprint(
    actor: &DfdNode,
    run_index: usize,
) -> String {
    let sanitized = actor
        .name
        .chars()
        .map(|ch| {
            if ch.is_whitespace() || ch == ':' {
                '_'
            } else {
                ch
            }
        })
        .collect::<String>();
    format!("{MODULE_ID}:{sanitized}:{run_index}")
}

pub(in crate::capabilities::carlini_threat_hunt) fn normalize_file_path(
    target: &Path,
    file_path: &str,
) -> Option<String> {
    let path = Path::new(file_path.trim());
    let relative = if path.is_absolute() {
        path.strip_prefix(target).ok()?
    } else {
        path
    };
    let mut normalized = PathBuf::new();
    for component in relative.components() {
        match component {
            std::path::Component::Normal(part) => normalized.push(part),
            std::path::Component::CurDir => {}
            _ => return None,
        }
    }
    (!normalized.as_os_str().is_empty()).then(|| normalized.display().to_string())
}
