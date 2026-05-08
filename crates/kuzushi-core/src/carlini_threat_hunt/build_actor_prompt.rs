use super::prelude::*;
use super::*;

pub(crate) fn build_actor_prompt(
    target: &Path,
    hunt: &ActorHunt,
    options: &CarliniInput,
    inventory: &[(String, String)],
    actor_fingerprint: &str,
) -> String {
    let mut lines = vec![
        format!(
            "IMPORTANT: Only examine files under {}. Do not read, grep, or navigate outside this directory.",
            target.display()
        ),
        String::new(),
    ];
    if let Some(block) = options
        .attachments_block
        .as_deref()
        .filter(|block| !block.trim().is_empty())
    {
        lines.push(block.to_string());
        lines.push(String::new());
    }
    lines.push(options.kb_context.render_prompt_block());
    lines.push(String::new());
    lines.extend([
        format!(
            "You are performing an authorized CTF-style security assessment. You are simulating: {}",
            hunt.actor.name
        ),
        format!("Description: {}", hunt.actor.description),
        format!("Resolved actor id: {}", hunt.actor.id),
        format!("Trust zone: {}", hunt.actor.trust_zone),
        format!("Actor activity fingerprint: {actor_fingerprint}"),
        "Use the linked flows and threat leads to reason about actor reachability before reporting.".to_string(),
        String::new(),
        "Linked data flows from the graph threat model:".to_string(),
    ]);
    if hunt.flows.is_empty() {
        lines.push("- (none linked)".to_string());
    } else {
        for flow in hunt.flows.iter().take(12) {
            let details = [
                flow.protocol
                    .as_ref()
                    .filter(|value| !value.is_empty())
                    .map(|value| format!("protocol={value}")),
                flow.data_classification
                    .as_ref()
                    .filter(|value| !value.is_empty())
                    .map(|value| format!("classification={value}")),
                (!flow.trust_boundary_ids.is_empty())
                    .then(|| format!("crosses={}", flow.trust_boundary_ids.join(", "))),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" ; ");
            lines.push(format!(
                "- {}: {} -> {} - {}{}",
                flow.id,
                flow.source_id,
                flow.target_id,
                flow.description,
                if details.is_empty() {
                    String::new()
                } else {
                    format!(" ({details})")
                }
            ));
        }
    }
    if options.debug_inline_threats || options.prompt_context == "actor-flows-threat-titles" {
        lines.push(String::new());
        lines.push("Linked threat leads:".to_string());
        if hunt.threats.is_empty() {
            lines.push("- (none linked)".to_string());
        }
        for threat in hunt.threats.iter().take(20) {
            let id = object_string_value(threat, &["id"]).unwrap_or_else(|| "unknown".to_string());
            let impact =
                object_string_value(threat, &["impact"]).unwrap_or_else(|| "medium".to_string());
            let category =
                object_string_value(threat, &["category"]).unwrap_or_else(|| "unknown".to_string());
            let title = object_string_value(threat, &["title"]).unwrap_or_else(|| id.clone());
            lines.push(format!(
                "- {id}: [{}/{category}] {title}",
                impact.to_ascii_uppercase()
            ));
            if options.debug_inline_threats {
                if let Some(attack_vector) =
                    object_string_value(threat, &["attackVector", "attack_vector"])
                {
                    lines.push(format!("  Attack vector: {attack_vector}"));
                }
            }
        }
    }
    lines.push(String::new());
    if let Some(override_prompt) = &options.prompt_override {
        lines.push(override_prompt.trim().to_string());
    } else {
        lines.extend([
            "Your mission: find additional evidence for the linked threat surface, discover new attack vectors in the same surface, or identify variants the threat model missed.".to_string(),
            "Do not re-confirm only what is already documented. Find something new or deeper.".to_string(),
            "Only report findings with concrete evidence of exploitability.".to_string(),
        ]);
    }
    lines.push(String::new());
    lines.push("Repository inventory and snippets:".to_string());
    if inventory.is_empty() {
        lines.push("(no readable source snippets found)".to_string());
    }
    for (path, snippet) in inventory {
        lines.push(format!("\n--- {path} ---\n{snippet}"));
    }
    lines.push(String::new());
    lines.push("Return exactly one JSON object and no prose. Use {\"findings\":[]} when there are no concrete exploitable findings.".to_string());
    lines.join("\n")
}
