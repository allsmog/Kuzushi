use serde_json::Value;

pub(super) fn picker_lines(picker: &crate::app::StudyContextPicker) -> Vec<String> {
    let Some(preview) = picker.preview.as_ref() else {
        return vec!["Select an exact context revision and press Enter to inspect it. No model request is made.".into()];
    };
    let mut lines = context_lines(&preview.scanner_context);
    lines.insert(0, preview.source_state.clone());
    if let Some(reference) = picker.selected.as_ref() {
        lines.extend([
            format!("Context revision: {}", reference.revision_id),
            format!("Document hash: {}", reference.sha256),
        ]);
    }
    lines
}

pub(super) fn context_lines(preview: &Value) -> Vec<String> {
    let mut lines = Vec::new();
    if !valid_preview(preview) {
        lines.push("Scanner projection is unavailable or malformed in this receipt. Enter rereads the exact revision. No context was substituted.".into());
        return lines;
    }
    append_strings(&mut lines, preview.get("limitations"));
    append_strings(&mut lines, preview.get("omissions"));
    lines.extend([
        String::new(),
        "THREAT-MODEL TEXT INCLUDED IN THE REQUEST".into(),
    ]);
    append_text(&mut lines, preview["text"].as_str());
    append_limits(&mut lines, &preview["limits"]);
    if let Some(hash) = preview["sha256"].as_str() {
        lines.push(format!("Digest text hash: {hash}"));
    }
    lines
}

fn valid_preview(preview: &Value) -> bool {
    if !valid_header(preview) {
        return false;
    }
    match preview.get("text") {
        Some(Value::String(text)) => {
            preview["sha256"].as_str() == Some(kuzushi_core::prompt_content_sha256(text).as_str())
        }
        Some(Value::Null) => preview["sha256"].is_null(),
        _ => false,
    }
}

fn valid_header(preview: &Value) -> bool {
    preview["schemaVersion"] == 1
        && preview["kind"] == "agentic-threat-model-digest"
        && valid_limits(&preview["limits"])
}

fn append_text(lines: &mut Vec<String>, text: Option<&str>) {
    match text {
        Some(text) => lines.extend(text.lines().map(str::to_owned)),
        None => lines.push("No threat-model digest text is included by this projection.".into()),
    }
}

fn valid_limits(limits: &Value) -> bool {
    [
        "threats",
        "itemsPerSection",
        "ordinaryFieldCharacters",
        "reviewedLessons",
        "lessonFieldCharacters",
    ]
    .into_iter()
    .all(|key| limits[key].as_u64().is_some_and(|value| value > 0))
}

fn append_strings(lines: &mut Vec<String>, values: Option<&Value>) {
    lines.extend(
        values
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned),
    );
}

fn append_limits(lines: &mut Vec<String>, limits: &Value) {
    lines.push(String::new());
    lines.push(format!("Projection limits: {} threats; {} items per other section. Selected ordinary fields and pattern code are capped at {} characters; other fields can appear in full.",limits["threats"],limits["itemsPerSection"],limits["ordinaryFieldCharacters"]));
    lines.push(format!(
        "Lesson limits: at most {}; {} characters per field. The saved document remains unchanged.",
        limits["reviewedLessons"], limits["lessonFieldCharacters"]
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn valid_projection_keeps_included_text_and_omissions_separate_from_full_document() {
        let text = "Modeled threats:\n- Owned review principle";
        let preview = json!({"schemaVersion":1,"kind":"agentic-threat-model-digest","text":text,"sha256":kuzushi_core::prompt_content_sha256(text),"omissions":["Threats: first 12 of 13 items; 1 omitted.", "Component 2 description: first 200 of 218 characters; 18 omitted.", "Variant patterns: first 12 of 13 items; 1 omitted."],"limitations":["Other engines may consume different context."],"limits":{"threats":12,"itemsPerSection":12,"ordinaryFieldCharacters":200,"reviewedLessons":8,"lessonFieldCharacters":2048}});
        let lines = context_lines(&preview).join("\n");
        assert!(lines.contains(text));
        assert!(lines.contains("1 omitted"));
        assert!(lines.contains("Other engines"));
        assert!(lines.contains("2048 characters"));
        assert!(lines.contains("Component 2 description"));
        assert!(lines.contains("Variant patterns: first 12 of 13"));
        assert!(lines.contains("other fields can appear in full"));
    }

    #[test]
    fn unavailable_and_tampered_receipts_never_show_a_substitute() {
        for preview in [
            Value::Null,
            json!({"schemaVersion":1,"kind":"agentic-threat-model-digest","text":"untrusted projection","sha256":"wrong"}),
        ] {
            let lines = context_lines(&preview).join("\n");
            assert!(lines.contains("Enter rereads"));
            assert!(!lines.contains("untrusted projection"));
        }
    }

    #[test]
    fn an_empty_projection_discloses_no_text_instead_of_using_the_document() {
        let preview = json!({"schemaVersion":1,"kind":"agentic-threat-model-digest","text":null,"sha256":null,"limits":{"threats":12,"itemsPerSection":12,"ordinaryFieldCharacters":200,"reviewedLessons":8,"lessonFieldCharacters":2048}});
        assert!(context_lines(&preview)
            .join("\n")
            .contains("No threat-model digest text"));
    }
}
