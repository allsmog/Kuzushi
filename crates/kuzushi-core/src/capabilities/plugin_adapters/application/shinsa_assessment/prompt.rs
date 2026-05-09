use super::*;

pub(super) struct ShinsaPromptInput<'a> {
    pub(super) tool_name: &'a str,
    pub(super) mode: &'a str,
    pub(super) output_dir: &'a str,
    pub(super) plugin_root: &'a Path,
    pub(super) input: &'a Value,
    pub(super) inventory: &'a [(String, String)],
}

pub(super) fn build_shinsa_prompt(input: &ShinsaPromptInput<'_>) -> String {
    let mut lines = vec![
        format!(
            "Run a {} compliance assessment over the provided repository snippets.",
            input.mode
        ),
        format!("Resolved plugin root: {}", input.plugin_root.display()),
        format!("Artifact output directory: {}", input.output_dir),
        "Ground every finding in file and line evidence. Do not speculate about unread code."
            .to_string(),
    ];
    push_optional_filter_lines(&mut lines, input.input);
    lines.push(String::new());
    lines.push("Repository inventory and snippets:".to_string());
    for (path, snippet) in input.inventory {
        lines.push(format!("\n--- {path} ---\n{snippet}"));
    }
    lines.join("\n")
}

fn push_optional_filter_lines(lines: &mut Vec<String>, input: &Value) {
    if let Some(controls) = string_array_or_csv_input(input, &["controls"]) {
        lines.push(format!("Controls filter: {}", controls.join(", ")));
    }
    if let Some(family) = string_input_any(input, &["family"]) {
        lines.push(format!("Family filter: {family}"));
    }
    if let Some(severity) = string_array_or_csv_input(input, &["severity"]) {
        lines.push(format!("Severity filter: {}", severity.join(", ")));
    }
}
