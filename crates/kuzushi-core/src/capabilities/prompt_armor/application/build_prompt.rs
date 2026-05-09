use serde_json::Value;
use std::path::Path;

pub(crate) fn build_prompt(
    command: &str,
    plugin_root: &Path,
    input: &Value,
    inventory: &[(String, String)],
) -> String {
    let mut lines = prompt_header(command, plugin_root);
    lines.extend(prompt_input_lines(input));
    lines.extend(inventory_prompt_lines(inventory));
    lines.join("\n")
}

fn prompt_header(command: &str, plugin_root: &Path) -> Vec<String> {
    vec![
        format!("Run PromptArmor /{command} using the provided inputs."),
        format!("Resolved plugin root: {}", plugin_root.display()),
        "For scan and attack, the caller has supplied the required authorization gate.".to_string(),
    ]
}

fn prompt_input_lines(input: &Value) -> impl Iterator<Item = String> + '_ {
    PROMPT_INPUT_KEYS.iter().filter_map(|key| {
        input
            .get(key)
            .map(|value| format!("{key}: {}", json_summary(value)))
    })
}

fn inventory_prompt_lines(inventory: &[(String, String)]) -> impl Iterator<Item = String> + '_ {
    std::iter::once(String::new())
        .chain(std::iter::once(
            "Repository inventory and snippets:".to_string(),
        ))
        .chain(
            inventory
                .iter()
                .map(|(path, snippet)| format!("\n--- {path} ---\n{snippet}")),
        )
}

const PROMPT_INPUT_KEYS: &[&str] = &[
    "endpoint",
    "suites",
    "mutations",
    "config",
    "paths",
    "focus",
    "attack",
    "mutation",
    "payload",
];

fn json_summary(value: &Value) -> String {
    value
        .as_str()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| value.to_string())
}
