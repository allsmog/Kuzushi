use super::*;
use serde_json::json;

fn rendered(kind: ReferenceKind, value: &Value) -> String {
    binding_lines("Context", kind, Some(value)).join("\n")
}

#[test]
fn scope_fields_keep_full_membership_identity_without_json_scaffolding() {
    let value = json!({"proposal":{"proposalId":"owned-proposal","revision":3,"recordHash":"full-record-hash"},"scopeId":"accounts"});
    let text = rendered(ReferenceKind::Scope, &value);
    for expected in [
        "Scope id: accounts",
        "Proposal id: owned-proposal",
        "Revision: 3",
        "Record hash: full-record-hash",
    ] {
        assert!(text.contains(expected), "{text}");
    }
    assert!(!text.contains('{') && !text.contains('}'), "{text}");
}

#[test]
fn architecture_and_supplemental_fields_preserve_complete_recorded_values() {
    let architecture = json!({"modelId":"recorded-model","revisionId":"frozen-revision","sha256":"sha256:complete-recorded-digest"});
    let text = rendered(ReferenceKind::Architecture, &architecture);
    for expected in [
        "Model id: recorded-model",
        "Revision id: frozen-revision",
        "SHA256: sha256:complete-recorded-digest",
    ] {
        assert!(text.contains(expected), "{text}");
    }
    let supplemental = json!({"schemaVersion":1,"object":{"kind":"blob","hash":"full-object-hash","sizeBytes":303}});
    let text = rendered(ReferenceKind::Supplemental, &supplemental);
    for expected in [
        "Schema: 1",
        "Object kind: blob",
        "Object hash: full-object-hash",
        "Bytes: 303",
    ] {
        assert!(text.contains(expected), "{text}");
    }
    assert!(!text.contains('{') && !text.contains('}'), "{text}");
}

#[test]
fn absent_omitted_and_unrecognized_values_remain_distinct() {
    assert_eq!(
        binding_lines("Context", ReferenceKind::Scope, None),
        ["Context: not recorded"]
    );
    assert_eq!(
        binding_lines("Context", ReferenceKind::Scope, Some(&Value::Null)),
        ["Context: explicitly omitted"]
    );
    for value in [
        json!({"scopeId":7}),
        json!(["legacy", 7]),
        json!("legacy reference"),
    ] {
        let text = rendered(ReferenceKind::Scope, &value);
        assert!(
            text.starts_with("Context: unrecognized recorded format"),
            "{text}"
        );
        let raw = text
            .lines()
            .skip(1)
            .map(|line| line.strip_prefix("  ").unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(serde_json::from_str::<Value>(&raw).unwrap(), value);
    }
}

#[test]
fn unknown_nested_and_top_level_fields_keep_their_raw_record() {
    for (kind, value) in [
        (
            ReferenceKind::Supplemental,
            json!({"schemaVersion":1,"object":{"kind":"blob","hash":"owned","sizeBytes":3,"future":"retained"}}),
        ),
        (
            ReferenceKind::Architecture,
            json!({"modelId":"owned","revisionId":"r1","sha256":"digest","future":{"retained":true}}),
        ),
        (
            ReferenceKind::Scope,
            json!({"scopeId":"owned","proposal":{"proposalId":"p","revision":1,"recordHash":"digest","future":"retained"}}),
        ),
    ] {
        let text = rendered(kind, &value);
        assert!(
            text.contains("unrecognized recorded format") && text.contains("future"),
            "{text}"
        );
        let raw = text
            .lines()
            .skip(1)
            .map(|line| line.strip_prefix("  ").unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(serde_json::from_str::<Value>(&raw).unwrap(), value);
    }
}

#[test]
fn reference_text_cannot_forge_document_rows_or_hide_literal_whitespace() {
    for value in [
        "",
        " leading ",
        "line\nbreak",
        "literal\\n",
        "tab\tvalue",
        "Unicode 東京",
        "escape\u{1b}[31m",
        "\"\"",
        "\"quoted\"",
    ] {
        let text = field("Model id", value);
        assert_eq!(text.lines().count(), 1, "{text:?}");
        assert!(!text.contains('\u{1b}') && !text.contains('\t'));
        let literal = text.strip_prefix("Model id: ").unwrap();
        let decoded = if literal.starts_with('"') {
            serde_json::from_str::<String>(literal).unwrap()
        } else {
            literal.to_owned()
        };
        assert_eq!(decoded, value);
    }
    assert_ne!(
        field("Model id", "line\nbreak"),
        field("Model id", "line\\nbreak")
    );
    assert_eq!(field("Model id", " leading "), "Model id: \" leading \"");
    assert_eq!(field("Model id", "Unicode東京"), "Model id: Unicode東京");
}
