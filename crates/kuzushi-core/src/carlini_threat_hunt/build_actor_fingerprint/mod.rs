use super::*;

mod file_filters;
mod input_options;
mod json_fields;
mod output_contract;
mod threat_metrics;

pub(in crate::carlini_threat_hunt) use file_filters::{is_context_file, should_skip_path};
#[cfg(test)]
pub(in crate::carlini_threat_hunt) use input_options::looks_like_prompt_path;
pub(in crate::carlini_threat_hunt) use input_options::{
    bool_input, optional_string, read_usize, resolve_prompt_override,
};
pub(in crate::carlini_threat_hunt) use json_fields::{
    object_string_array, object_string_value, read_object_string, read_object_string_array,
    read_object_u64, unique_strings,
};
pub(in crate::carlini_threat_hunt) use output_contract::{findings_schema, require_json_object};
pub(in crate::carlini_threat_hunt) use threat_metrics::{carlini_severity, critical_count};

pub(in crate::carlini_threat_hunt) fn build_actor_fingerprint(
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

pub(in crate::carlini_threat_hunt) fn normalize_file_path(
    target: &Path,
    file_path: &str,
) -> Option<String> {
    let path = PathBuf::from(file_path.trim());
    if path.is_absolute() {
        return path
            .strip_prefix(target)
            .ok()
            .map(|path| path.display().to_string());
    }
    if file_path.trim().starts_with("..") {
        return None;
    }
    Some(file_path.trim().to_string())
}
