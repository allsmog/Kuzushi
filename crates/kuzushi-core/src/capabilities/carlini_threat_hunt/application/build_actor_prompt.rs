use super::*;

pub(crate) fn build_actor_prompt(
    target: &Path,
    hunt: &ActorHunt,
    options: &CarliniInput,
    inventory: &[(String, String)],
    actor_fingerprint: &str,
) -> String {
    let mut lines = actor_prompt_header(target, hunt, options, actor_fingerprint);
    append_actor_flows(&mut lines, hunt);
    append_actor_threats(&mut lines, hunt, options);
    append_actor_mission(&mut lines, options);
    append_actor_inventory(&mut lines, inventory);
    lines.push("Return exactly one JSON object and no prose. Use {\"findings\":[]} when there are no concrete exploitable findings.".to_string());
    lines.join("\n")
}

fn actor_prompt_header(
    target: &Path,
    hunt: &ActorHunt,
    options: &CarliniInput,
    actor_fingerprint: &str,
) -> Vec<String> {
    let mut lines = vec![actor_prompt_target_rule(target), String::new()];
    append_actor_attachments(&mut lines, options);
    append_actor_context(&mut lines, options);
    lines.extend(actor_identity_lines(hunt, actor_fingerprint));
    lines
}

fn actor_prompt_target_rule(target: &Path) -> String {
    format!(
        "IMPORTANT: Only examine files under {}. Do not read, grep, or navigate outside this directory.",
        target.display()
    )
}

fn append_actor_attachments(lines: &mut Vec<String>, options: &CarliniInput) {
    if let Some(block) = non_empty_attachment_block(options) {
        lines.push(block.to_string());
        lines.push(String::new());
    }
}

fn non_empty_attachment_block(options: &CarliniInput) -> Option<&str> {
    options
        .attachments_block
        .as_deref()
        .filter(|block| !block.trim().is_empty())
}

fn append_actor_context(lines: &mut Vec<String>, options: &CarliniInput) {
    lines.push(options.kb_context.render_prompt_block());
    lines.push(String::new());
}

fn actor_identity_lines(hunt: &ActorHunt, actor_fingerprint: &str) -> [String; 8] {
    [
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
    ]
}

fn append_actor_mission(lines: &mut Vec<String>, options: &CarliniInput) {
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
}

fn append_actor_inventory(lines: &mut Vec<String>, inventory: &[(String, String)]) {
    lines.push(String::new());
    lines.push("Repository inventory and snippets:".to_string());
    if inventory.is_empty() {
        lines.push("(no readable source snippets found)".to_string());
    }
    for (path, snippet) in inventory {
        lines.push(format!("\n--- {path} ---\n{snippet}"));
    }
    lines.push(String::new());
}
