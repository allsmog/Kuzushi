//! Names only fields the execution renderer selects, without changing its text.
use crate::capabilities::agentic_sast::{
    select_threat_digest_field, MAX_DIGEST_ENTRIES, MAX_DIGEST_FIELD_CHARS, MAX_DIGEST_THREATS,
};
use serde_json::Value;

struct Section {
    label: &'static str,
    limit: usize,
    pointer: &'static str,
    required: &'static [&'static [&'static str]],
    fields: &'static [&'static [&'static str]],
}

const SECTIONS: &[Section] = &[
    Section {
        label: "Threat",
        limit: MAX_DIGEST_THREATS,
        pointer: "/threats",
        required: &[],
        fields: &[
            &["severity", "likelihood"],
            &["title", "description", "id"],
            &["relatedCwe", "relatedCwes", "cwe"],
            &["affectedFiles"],
        ],
    },
    Section {
        label: "Entry point",
        limit: MAX_DIGEST_ENTRIES,
        pointer: "/attackSurface/entryPoints",
        required: &[],
        fields: &[&["name"], &["trustZone"], &["evidence"]],
    },
    Section {
        label: "External sink",
        limit: MAX_DIGEST_ENTRIES,
        pointer: "/attackSurface/externalSinks",
        required: &[],
        fields: &[&["name"], &["category"]],
    },
    Section {
        label: "Component",
        limit: MAX_DIGEST_ENTRIES,
        pointer: "/dfd/nodes",
        required: &[&["name", "id"]],
        fields: &[&["name", "id"], &["trustZone"], &["description"]],
    },
    Section {
        label: "Data flow",
        limit: MAX_DIGEST_ENTRIES,
        pointer: "/dfd/flows",
        required: &[&["sourceId"], &["targetId"]],
        fields: &[&["sourceId"], &["targetId"], &["description"]],
    },
    Section {
        label: "Trust boundary",
        limit: MAX_DIGEST_ENTRIES,
        pointer: "/dfd/trustBoundaries",
        required: &[&["name", "id"]],
        fields: &[&["name", "id"], &["description"]],
    },
];

pub(super) fn collect(document: &Value) -> Vec<String> {
    let mut notices = Vec::new();
    for section in SECTIONS {
        for (index, item) in items(document.pointer(section.pointer), section.limit).enumerate() {
            notices.extend(item_notices(section, index, item));
        }
    }
    notices.extend(question_notices(document));
    notices
}

fn items(value: Option<&Value>, limit: usize) -> impl Iterator<Item = &Value> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(limit)
}

fn item_notices(section: &Section, index: usize, item: &Value) -> Vec<String> {
    if !section
        .required
        .iter()
        .all(|keys| select_threat_digest_field(item, keys).is_some())
    {
        return Vec::new();
    }
    section
        .fields
        .iter()
        .filter_map(|keys| select_threat_digest_field(item, keys))
        .filter_map(|(key, text)| {
            character_notice(&format!("{} {} {key}", section.label, index + 1), &text)
        })
        .collect()
}

fn question_notices(document: &Value) -> Vec<String> {
    items(document.get("openQuestions"), MAX_DIGEST_ENTRIES)
        .enumerate()
        .filter_map(|(index, question)| {
            character_notice(&format!("Open question {}", index + 1), question.as_str()?)
        })
        .collect()
}

pub(super) fn character_notice(label: &str, text: &str) -> Option<String> {
    character_count_notice(label, text.chars().count())
}

pub(super) fn character_count_notice(label: &str, count: usize) -> Option<String> {
    (count > MAX_DIGEST_FIELD_CHARS).then(|| {
        format!(
            "{label}: first {MAX_DIGEST_FIELD_CHARS} of {count} characters; {} omitted.",
            count - MAX_DIGEST_FIELD_CHARS
        )
    })
}
