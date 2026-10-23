//! Explain actual file evidence separately from inherited architecture.
use serde_json::Value;

pub(super) fn receipt_lines(document: &Value) -> Vec<String> {
    let Some(receipt) = document.pointer("/provenance/fileContext/receipt") else {
        return Vec::new();
    };
    let source = &receipt["sourceEvidence"];
    let mut lines = vec![
        String::new(),
        "EVIDENCE CONTEXT RECEIPT".into(),
        format!(
            "Requested files: {} · supplied excerpts: {}",
            receipt["selectedFileCount"],
            source["files"].as_array().map_or(0, Vec::len)
        ),
        format!(
            "Selected source partial: {} · complete repository coverage: false",
            receipt["sourcePartial"]
        ),
        format!(
            "Inherited architecture: {}",
            receipt["inheritedContextRef"]["revisionId"]
        ),
        "Inherited text is context; only the listed excerpts supply source evidence.".into(),
    ];
    lines.extend(super::super::evidence_inventory::receipt_lines(
        receipt.get("inventory"),
    ));
    for file in source["files"].as_array().into_iter().flatten() {
        lines.push(format!("  {}", file["path"]));
    }
    lines.push(format!("Source omissions: {}", source["omissions"]));
    lines.push(
        "Tab reads the complete document, including frozen excerpts and the generation receipt."
            .into(),
    );
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn partial_evidence_summary_keeps_literal_names_and_inheritance_separate() {
        let document = json!({"provenance":{"fileContext":{"receipt":{"selectedFileCount":2,"sourcePartial":true,
            "inheritedContextRef":{"revisionId":"exact-parent"},"sourceEvidence":{"files":[{"path":" app /one.rs"}],"omissions":{"file limit":1}}}}}});
        let text = receipt_lines(&document).join("\n");
        assert!(text.contains("Requested files: 2 · supplied excerpts: 1"));
        assert!(
            text.contains("Selected source partial: true · complete repository coverage: false")
        );
        assert!(text.contains("\" app /one.rs\""));
        assert!(text.contains("exact-parent") && text.contains("file limit"));
    }
}
