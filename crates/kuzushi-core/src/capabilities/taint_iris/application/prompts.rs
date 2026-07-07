use super::*;

pub(crate) fn taint_cwe_selection_schema() -> Value {
    json!({
        "type": "object",
        "required": ["cwes"],
        "additionalProperties": true,
        "properties": {
            "cwes": {
                "type": "array",
                "items": {
                    "oneOf": [
                        {"type": "string"},
                        {
                            "type": "object",
                            "required": ["id"],
                            "additionalProperties": true,
                            "properties": {
                                "id": {"type": "string"},
                                "name": {"type": "string"},
                                "reason": {"type": "string"}
                            }
                        }
                    ]
                }
            }
        }
    })
}

pub(crate) fn build_taint_cwe_select_prompt(
    target: &Path,
    inventory: &[(String, String)],
) -> String {
    let mut prompt = vec![
        "Select the CWE classes that deserve IRIS-style taint analysis for this repository."
            .to_string(),
        format!("Target: {}", target.display()),
        "Prefer source-to-sink classes such as injection, traversal, SSRF, deserialization, and unsafe code execution when the snippets support them.".to_string(),
    ];
    append_inventory(&mut prompt, inventory);
    prompt.join("\n")
}

fn append_inventory(prompt: &mut Vec<String>, inventory: &[(String, String)]) {
    prompt.push(String::new());
    prompt.push("Repository inventory and snippets:".to_string());
    if inventory.is_empty() {
        prompt.push("(no readable source snippets found)".to_string());
    }
    for (path, snippet) in inventory {
        prompt.push(format!("\n--- {path} ---\n{snippet}"));
    }
}
