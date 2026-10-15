//! Read-only projection of the existing execution renderer, without prompt changes.
use crate::capabilities::agentic_sast::{
    MAX_DIGEST_ENTRIES, MAX_DIGEST_FIELD_CHARS, MAX_DIGEST_LESSONS, MAX_DIGEST_LESSON_FIELD_CHARS,
    MAX_DIGEST_THREATS,
};
use serde_json::{json, Value};
mod field_omissions;

const COUNTED_SECTIONS: &[(&str, &str, usize)] = &[
    ("Threats", "/threats", MAX_DIGEST_THREATS),
    (
        "Entry points",
        "/attackSurface/entryPoints",
        MAX_DIGEST_ENTRIES,
    ),
    (
        "External sinks",
        "/attackSurface/externalSinks",
        MAX_DIGEST_ENTRIES,
    ),
    ("Components", "/dfd/nodes", MAX_DIGEST_ENTRIES),
    ("Data flows", "/dfd/flows", MAX_DIGEST_ENTRIES),
    (
        "Trust boundaries",
        "/dfd/trustBoundaries",
        MAX_DIGEST_ENTRIES,
    ),
    ("Open questions", "/openQuestions", MAX_DIGEST_ENTRIES),
    ("Reviewed lessons", "/reviewedLessons", MAX_DIGEST_LESSONS),
];

pub(crate) fn build(document: &Value) -> Value {
    let text = crate::capabilities::agentic_sast::render_threat_model_digest(document);
    let sha256 = text.as_deref().map(crate::options::prompt_content_sha256);
    json!({
        "schemaVersion":1,
        "kind":"agentic-threat-model-digest",
        "text":text,
        "sha256":sha256,
        "omissions":omissions(document),
        "limits":{
            "threats":MAX_DIGEST_THREATS,"itemsPerSection":MAX_DIGEST_ENTRIES,"ordinaryFieldCharacters":MAX_DIGEST_FIELD_CHARS,
            "reviewedLessons":MAX_DIGEST_LESSONS,"lessonFieldCharacters":MAX_DIGEST_LESSON_FIELD_CHARS
        },
        "limitations":[
            "Used by agentic scans and model triage. Other engines may consume different context.",
            "This is the threat-model portion of a request. Source files, supporting context and prompt overrides are separate.",
            "Only the displayed digest text is included by this projection. Other saved document fields are omitted.",
            "Runtime repeats source and lesson checks. It can prepend a validation warning or refuse execution. Reading starts no work."
        ]
    })
}

fn omissions(document: &Value) -> Vec<String> {
    let mut omitted = Vec::new();
    for &(label, pointer, limit) in COUNTED_SECTIONS {
        let count = document
            .pointer(pointer)
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        if count > limit {
            omitted.push(format!(
                "{label}: first {limit} of {count} items; {} omitted.",
                count - limit
            ));
        }
    }
    omitted.extend(lesson_omissions(document));
    omitted.extend(field_omissions::collect(document));
    omitted.extend(variant_omissions(document));
    omitted
}

fn variant_omissions(document: &Value) -> Vec<String> {
    let patterns = crate::capabilities::threat_model::threat_variant_patterns(document);
    let mut notices = Vec::new();
    if patterns.len() > MAX_DIGEST_ENTRIES {
        notices.push(format!(
            "Variant patterns: first {MAX_DIGEST_ENTRIES} of {} items; {} omitted.",
            patterns.len(),
            patterns.len() - MAX_DIGEST_ENTRIES
        ));
    }
    for (count, indexes) in variant_code_cuts(&patterns) {
        let indexes = indexes
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        notices.extend(field_omissions::character_count_notice(
            &format!("Variant pattern code fields {indexes} (each)"),
            count,
        ));
    }
    notices
}

fn variant_code_cuts(patterns: &[&Value]) -> std::collections::BTreeMap<usize, Vec<usize>> {
    let mut groups = std::collections::BTreeMap::<usize, Vec<usize>>::new();
    for (index, pattern) in patterns.iter().take(MAX_DIGEST_ENTRIES).enumerate() {
        let Some(code) = pattern.get("code").and_then(Value::as_str) else {
            continue;
        };
        let count = code.chars().count();
        if count > MAX_DIGEST_FIELD_CHARS {
            groups.entry(count).or_default().push(index + 1);
        }
    }
    groups
}

fn lesson_omissions(document: &Value) -> Vec<String> {
    document
        .get("reviewedLessons")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_DIGEST_LESSONS)
        .enumerate()
        .flat_map(|(index, record)| {
            ["title", "text", "applicability", "limitations"]
                .into_iter()
                .filter_map(move |key| lesson_field_omission(index, key, &record["content"]))
        })
        .collect()
}

fn lesson_field_omission(index: usize, key: &str, content: &Value) -> Option<String> {
    let count = content[key].as_str()?.chars().count();
    (count>MAX_DIGEST_LESSON_FIELD_CHARS).then(||format!("Lesson {} {key}: first {MAX_DIGEST_LESSON_FIELD_CHARS} of {count} characters; {} omitted.",index+1,count-MAX_DIGEST_LESSON_FIELD_CHARS))
}

#[cfg(test)]
mod tests;
