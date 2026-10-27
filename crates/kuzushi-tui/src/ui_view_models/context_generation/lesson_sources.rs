use kuzushi_core::run_lifecycle::SafeText;
use serde_json::Value;

pub(crate) fn lesson_source_lines(document: &Value) -> Vec<String> {
    let mut lines = vec![
        "HISTORICAL LESSON SOURCE".into(),
        "Read only · Esc plan · PgUp/PgDn read · Home/End".into(),
        format!(
            "Recorded observation: {}",
            document
                .pointer("/origin/observationSeq")
                .unwrap_or(&Value::Null)
        ),
        format!(
            "Shared source limit: {} bytes. No current checkout text is substituted.",
            document["maxBytes"]
        ),
        String::new(),
    ];
    append_file(&mut lines, "Cited file", &document["primary"]);
    for (index, file) in document["supporting"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
    {
        append_file(&mut lines, &format!("Supporting file {}", index + 1), file);
    }
    lines
}

fn append_file(lines: &mut Vec<String>, label: &str, file: &Value) {
    lines.push(format!(
        "{label}: {}",
        SafeText::operator_visible(file["path"].to_string())
    ));
    let Some(text) = file["text"].as_str() else {
        lines.push(omission_label(file["status"].as_str()).into());
        lines.push(String::new());
        return;
    };
    lines.push(format!("Included: {} historical bytes", text.len()));
    lines.extend(
        SafeText::document_lines(text)
            .into_iter()
            .map(|line| line.to_string()),
    );
    lines.push(String::new());
}

fn omission_label(status: Option<&str>) -> &'static str {
    match status {
        Some("not_recorded") => "Omitted: no retained source membership for this path.",
        Some("unavailable_or_over_limit") => {
            "Omitted: capture unavailable, binary, invalid text or over the shared byte limit."
        }
        _ => "Omitted: capture state unavailable. Inspect the recorded receipt.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn source_reader_preserves_source_lines_and_explains_each_omission() {
        let document = json!({"maxBytes":1024,"primary":{"path":"route.rs","text":"  first line\n\tsecond line\n"},"supporting":[{"path":"deleted.rs","text":"historical text\n"},{"path":"missing.rs","status":"not_recorded","text":null},{"path":"large.rs","status":"unavailable_or_over_limit","text":null}]});
        let lines = lesson_source_lines(&document);
        let text = lines.join("\n");
        assert!(lines.iter().any(|line| line == "  first line"));
        assert!(text.contains("historical text"));
        assert!(text.contains("no retained source membership"));
        assert!(text.contains("over the shared byte limit"));
        assert!(!text.contains("currentSourceRead"));
    }
}
