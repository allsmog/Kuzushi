//! Chat tab model: transcript, prompts for the real model, and the
//! structured actions the model may propose (refine / threat edits). Every
//! proposed change is confirmed by the operator before it is applied.

use serde_json::{Map, Value};

pub enum Msg {
    User(String),
    /// Markdown answer (action block stripped).
    Assistant(String),
    /// `⎿ Read(src/app.rs)` tool call.
    Tool(String),
    /// Workflow event (version created, activated, …).
    Event(String),
    Error(String),
}

pub enum Proposal {
    Refine { seed: String },
    UpdateThreats { summary: String, updates: Vec<Value> },
}

pub const CHAT_SYSTEM: &str = r#"You are Kuzushi's threat-model assistant, running inside a terminal UI next to the operator's threat model.
The operator consults THREAT_MODEL.md (8 fixed sections: §1 System context, §2 Assets, §3 Entry points & trust boundaries, §4 Threats, §5 Deprioritized, §6 Open questions, §7 Provenance, §8 Recommended mitigations).

Answer like a senior application-security engineer: direct, specific, concise. Use GitHub markdown suited to a terminal (short paragraphs, bullets, small tables). Cite sections (§4) and threat ids (T-1). Your working directory is the target repository when one exists: use Read/Grep/Glob to ground answers in code and cite file:line. Read any attached design docs before answering. Never invent components that are in neither the model nor the code — say what is unknown.

You cannot modify the model yourself. When the operator describes a change to the system, answers an open question, or asks you to update the model, explain briefly what should change, then end your reply with exactly one fenced block, either:

```kuzushi-action
{"action":"refine","seed":"<precise, self-contained instruction for a threat-model refine: what changed, where (files/endpoints), which components, flows, assets and threats to add or update>"}
```

or, for small precise edits to existing threats only (status, impact, likelihood, title, existingMitigations):

```kuzushi-action
{"action":"update_threats","summary":"<one line>","updates":[{"id":"T-2","status":"mitigated","existingMitigations":["..."]}]}
```

Emit an action block only when the operator wants the model changed."#;

pub const REFINE_SYSTEM: &str = r#"You update Kuzushi threat-model documents (JSON). You receive the current document and operator context (plus attached files you may Read, and a repository you may inspect with Read/Grep/Glob).
Return ONLY a JSON object — no prose, no code fence — containing the top-level keys you changed, each with its COMPLETE new value (arrays replace wholesale). Allowed keys: systemContext, assets, attackSurface, threats, deprioritized, openQuestions, recommendedMitigations, dfd.
Rules:
- Keep every existing id / stableId / displayId stable; change only what the context justifies.
- New threat: id and displayId "T-<n>" (next free number), stableId "st-T-<n>", title, actor, surface, asset, impact (critical|high|medium|low), likelihood (almost_certain|likely|possible|rare|very_rare), status (unmitigated|partially_mitigated|mitigated|risk_accepted), existingMitigations [], evidence [] (file:line strings when known), targetElementIds referencing dfd node/flow ids.
- New DFD node: id, name, type (external-entity|process|data-store), trustZone, purpose, description. New flow: id "<src>-><dst>", sourceId, targetId, description.
- New asset: id, asset, description, sensitivity, targetElementIds. New entry point (attackSurface.entryPoints): id, name, description, trustZone, reachableAssets, targetElementIds.
- Record unresolved assumptions in openQuestions ({"question": "..."})."#;

pub fn chat_prompt(question: &str, model_context: Option<&str>, attachments: &[String]) -> String {
    let mut prompt = String::new();
    if let Some(md) = model_context {
        prompt.push_str("<threat_model>\n");
        prompt.push_str(md);
        prompt.push_str("\n</threat_model>\n\n");
    }
    if !attachments.is_empty() {
        prompt.push_str("Attached design docs (read them):\n");
        for path in attachments {
            prompt.push_str(&format!("- {path}\n"));
        }
        prompt.push('\n');
    }
    prompt.push_str(question);
    prompt
}

pub fn refine_prompt(document: &Value, seed: &str, attachments: &[String]) -> String {
    let mut prompt = format!(
        "Current threat-model document:\n{}\n\nOperator context for this refine:\n{seed}\n",
        serde_json::to_string(document).unwrap_or_default()
    );
    if !attachments.is_empty() {
        prompt.push_str("\nAttached design docs (Read them before editing):\n");
        for path in attachments {
            prompt.push_str(&format!("- {path}\n"));
        }
    }
    prompt.push_str("\nReturn only the JSON object of changed top-level keys.");
    prompt
}

/// Split the model's reply into display markdown and an optional action.
pub fn split_action(reply: &str) -> (String, Result<Option<Proposal>, String>) {
    let Some(start) = reply.find("```kuzushi-action") else {
        return (reply.trim().to_string(), Ok(None));
    };
    let body_start = start + "```kuzushi-action".len();
    let end = reply[body_start..].find("```").map(|e| body_start + e).unwrap_or(reply.len());
    let json = reply[body_start..end].trim();
    let text = format!("{}{}", &reply[..start], reply.get(end + 3..).unwrap_or("")).trim().to_string();
    (text, parse_action(json))
}

fn parse_action(json: &str) -> Result<Option<Proposal>, String> {
    let value: Value = serde_json::from_str(json).map_err(|e| format!("model proposed an unreadable action: {e}"))?;
    match value.get("action").and_then(Value::as_str) {
        Some("refine") => Ok(value
            .get("seed")
            .and_then(Value::as_str)
            .map(|seed| Proposal::Refine { seed: seed.to_string() })),
        Some("update_threats") => Ok(Some(Proposal::UpdateThreats {
            summary: value.get("summary").and_then(Value::as_str).unwrap_or("edit threats").to_string(),
            updates: value.get("updates").and_then(Value::as_array).cloned().unwrap_or_default(),
        })),
        other => Err(format!("model proposed an unknown action {other:?}")),
    }
}

/// Parse a refine reply: the first `{` … last `}` must be a JSON object of
/// allowed top-level keys.
pub fn parse_refine_patch(reply: &str) -> Result<Map<String, Value>, String> {
    let Some(start) = reply.find('{') else {
        return Err("refine reply contained no JSON object".into());
    };
    // The first complete JSON value; models sometimes add prose after it.
    let value: Value = serde_json::Deserializer::from_str(&reply[start..])
        .into_iter::<Value>()
        .next()
        .ok_or("refine reply contained no JSON object")?
        .map_err(|e| format!("refine reply was not valid JSON: {e}"))?;
    let Value::Object(map) = value else { return Err("refine reply was not a JSON object".into()) };
    const ALLOWED: [&str; 8] = ["systemContext", "assets", "attackSurface", "threats", "deprioritized", "openQuestions", "recommendedMitigations", "dfd"];
    if let Some(bad) = map.keys().find(|k| !ALLOWED.contains(&k.as_str())) {
        return Err(format!("refine tried to change a disallowed key {bad:?}"));
    }
    if map.is_empty() {
        return Err("refine proposed no changes".into());
    }
    Ok(map)
}

/// Apply `update_threats` field edits by id / displayId / stableId.
pub fn apply_threat_updates(document: &Value, updates: &[Value]) -> Result<Value, String> {
    let mut next = document.clone();
    let threats = next.get_mut("threats").and_then(Value::as_array_mut).ok_or("document has no threats")?;
    for update in updates {
        let id = update.get("id").and_then(Value::as_str).ok_or("update without id")?;
        let threat = threats
            .iter_mut()
            .find(|t| ["id", "displayId", "stableId"].iter().any(|k| t.get(*k).and_then(Value::as_str) == Some(id)))
            .ok_or_else(|| format!("no threat {id} in the model"))?;
        for (k, v) in update.as_object().into_iter().flatten().filter(|(k, _)| k.as_str() != "id") {
            threat[k.as_str()] = v.clone();
        }
    }
    Ok(next)
}
