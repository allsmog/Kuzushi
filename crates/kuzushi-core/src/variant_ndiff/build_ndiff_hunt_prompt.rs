use super::prelude::*;
use super::*;

pub(crate) fn build_ndiff_hunt_prompt(
    pattern: &Map<String, Value>,
    advisory_id: &str,
    include_vendored: bool,
) -> String {
    let scope = if include_vendored {
        "Extend search to vendored code: node_modules/, vendor/, third_party/, deps/, external/."
    } else {
        "Restrict search to first-party source; skip node_modules/, vendor/, third_party/."
    };
    [
        "Hunt for pre-patch variants of a known advisory.",
        "Find code in the target repository that still has the vulnerable shape and lacks the fix shape.",
        "",
        &format!("Advisory: {advisory_id}"),
        "",
        "Fix-shape signature:",
        &format!(
            "Fix shape:        {}",
            read_object_string(pattern, &["fixShape", "fix_shape"]).unwrap_or_default()
        ),
        &format!(
            "Vulnerable shape: {}",
            read_object_string(pattern, &["vulnerableShape", "vulnerable_shape"])
                .unwrap_or_default()
        ),
        &format!(
            "CWEs:             {}",
            read_object_string_array(pattern, &["cwe", "cwes"]).join(", ")
        ),
        &format!(
            "Languages:        {}",
            read_object_string_array(pattern, &["languages"]).join(", ")
        ),
        &format!(
            "Keywords:         {}",
            read_object_string_array(pattern, &["keywords"]).join(", ")
        ),
        &format!(
            "Detection query:  {}",
            read_object_string(pattern, &["detectionQuery", "detection_query"]).unwrap_or_default()
        ),
        &read_object_string(pattern, &["description"]).unwrap_or_default(),
        "",
        "Methodology:",
        "1. Grep with the supplied keywords and detection query.",
        "2. Read each candidate file.",
        "3. Report only if the vulnerable shape is present and the fix shape is absent.",
        "4. Skip LOW confidence candidates.",
        scope,
    ]
    .join("\n")
}
