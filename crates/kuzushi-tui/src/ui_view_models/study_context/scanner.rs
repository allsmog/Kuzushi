use serde_json::Value;

pub(super) fn picker_lines(picker: &crate::app::StudyContextPicker) -> Vec<String> {
    let Some(preview) = picker.preview.as_ref() else {
        return vec!["Select an exact context revision and press Enter to inspect it. No model request is made.".into()];
    };
    let mut lines = context_lines(&preview.scanner_context);
    if !valid_preview(&preview.scanner_context) {
        return lines;
    }
    lines.insert(0, source_summary(&preview.scanner_context).into());
    let source = frozen_source_notice(&preview.scanner_context).unwrap_or(&preview.source_state);
    lines.push(source.to_string());
    if let Some(reference) = picker.selected.as_ref() {
        lines.extend([
            format!("Context revision: {}", reference.revision_id),
            format!("Document hash: {}", reference.sha256),
        ]);
    }
    lines
}

fn source_summary(preview: &Value) -> &'static str {
    if preview["origin"] != "frozen-study" {
        return "Revision preview; not frozen for a job.";
    }
    match preview["sourceMatchesAtInspection"].as_bool() {
        Some(true) => "Saved text; source matches at read.",
        Some(false) => "Earlier source; read only. Replan.",
        None => "Source unchecked; read only. Replan.",
    }
}

fn frozen_source_notice(preview: &Value) -> Option<&'static str> {
    if preview["origin"] != "frozen-study" {
        return None;
    }
    Some(match preview["sourceMatchesAtInspection"].as_bool() {
        Some(true) => "Saved scanner text matches this source at inspection. Context claims still require independent review.",
        Some(false) => "Saved scanner text belongs to earlier source. Reading is historical; execution requires a new plan.",
        None => "Saved scanner source could not be checked. Treat this text as historical before further work.",
    })
}

pub(super) fn context_lines(preview: &Value) -> Vec<String> {
    let mut lines = Vec::new();
    if !valid_preview(preview) {
        lines.push("Scanner projection is unavailable or malformed in this receipt. Enter rereads the exact revision. No context was substituted.".into());
        return lines;
    }
    lines.push("THREAT-MODEL TEXT INCLUDED".into());
    append_text(&mut lines, preview["text"].as_str());
    lines.extend([String::new(), "CONTEXT DETAILS AND LIMITS".into()]);
    if preview["origin"] == "frozen-study" {
        lines.push(
            "Saved scanner text for this study. Renderer updates do not replace these bytes."
                .into(),
        );
    }
    append_strings(&mut lines, preview.get("limitations"));
    append_strings(&mut lines, preview.get("omissions"));
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
    fn saved_source_notices_distinguish_current_historical_and_unknown_inspections() {
        for (state, expected) in [
            (json!(true), "matches this source"),
            (json!(false), "belongs to earlier source"),
            (Value::Null, "could not be checked"),
        ] {
            let preview = json!({"origin":"frozen-study","sourceMatchesAtInspection":state});
            assert!(frozen_source_notice(&preview).unwrap().contains(expected));
        }
        assert!(frozen_source_notice(&json!({})).is_none());
    }

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
        assert!(lines.find(text) < lines.find("Other engines"));
        assert!(lines.find(text) < lines.find("1 omitted"));
        assert!(lines.find(text) < lines.find("Projection limits:"));
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

    #[test]
    fn compact_source_status_never_implies_current_source_for_historical_or_unchecked_text() {
        for (state, expected) in [
            (json!(true), "source matches at read"),
            (json!(false), "Earlier source; read only"),
            (Value::Null, "Source unchecked; read only"),
        ] {
            let preview = json!({"origin":"frozen-study","sourceMatchesAtInspection":state});
            let summary = source_summary(&preview);
            assert!(summary.contains(expected), "{summary}");
            assert!(summary.len() <= 36);
        }
        assert_eq!(
            source_summary(&json!({})),
            "Revision preview; not frozen for a job."
        );
    }
}
