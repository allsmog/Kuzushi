use super::*;

pub(crate) fn append_actor_threats(
    lines: &mut Vec<String>,
    hunt: &ActorHunt,
    options: &CarliniInput,
) {
    if !include_actor_threats(options) {
        return;
    }
    append_actor_threat_block(lines, hunt, options.debug_inline_threats);
}

fn include_actor_threats(options: &CarliniInput) -> bool {
    options.debug_inline_threats || options.prompt_context == "actor-flows-threat-titles"
}

fn append_actor_threat_block(lines: &mut Vec<String>, hunt: &ActorHunt, debug_inline: bool) {
    lines.push(String::new());
    lines.push("Linked threat leads:".to_string());
    if hunt.threats.is_empty() {
        lines.push("- (none linked)".to_string());
    }
    for threat in hunt.threats.iter().take(20) {
        append_actor_threat(lines, threat, debug_inline);
    }
}

fn append_actor_threat(lines: &mut Vec<String>, threat: &Value, debug_inline: bool) {
    let id = object_string_value(threat, &["id"]).unwrap_or_else(|| "unknown".to_string());
    let impact = object_string_value(threat, &["impact"]).unwrap_or_else(|| "medium".to_string());
    let category =
        object_string_value(threat, &["category"]).unwrap_or_else(|| "unknown".to_string());
    let title = object_string_value(threat, &["title"]).unwrap_or_else(|| id.clone());
    lines.push(format!(
        "- {id}: [{}/{category}] {title}",
        impact.to_ascii_uppercase()
    ));
    append_actor_attack_vector(lines, threat, debug_inline);
}

fn append_actor_attack_vector(lines: &mut Vec<String>, threat: &Value, debug_inline: bool) {
    if !debug_inline {
        return;
    }
    if let Some(attack_vector) = object_string_value(threat, &["attackVector", "attack_vector"]) {
        lines.push(format!("  Attack vector: {attack_vector}"));
    }
}
