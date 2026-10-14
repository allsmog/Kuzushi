use serde_json::Value;

pub(crate) fn context_goal_lines(state: &Value) -> Vec<String> {
    let status = state["status"].as_str();
    if matches!(status, None | Some("absent")) {
        return Vec::new();
    }
    if status != Some("recorded") {
        return unavailable_lines(state);
    }
    vec![
        "RECORDED GOAL GUIDANCE".into(),
        format!(
            "{} · exact revision {} · {} text bytes",
            state
                .pointer("/reference/briefId")
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
            state
                .pointer("/reference/revision")
                .and_then(Value::as_u64)
                .map_or("unknown".into(), |revision| revision.to_string()),
            state["textBytes"]
                .as_u64()
                .map_or("unknown".into(), |bytes| bytes.to_string())
        ),
        "Saved goal reference authenticated. Model use is not independently verified by this read."
            .into(),
        "Historical priorities and questions. Source claims and finding verdicts require evidence:"
            .into(),
        state["text"]
            .as_str()
            .unwrap_or("Goal text unavailable.")
            .into(),
    ]
}

fn unavailable_lines(state: &Value) -> Vec<String> {
    let label = match state["status"].as_str() {
        Some("omitted") => "context explicitly omitted",
        Some("unbound") => "historical context not bound",
        _ => "unavailable",
    };
    vec![
        format!("RECORDED GOAL GUIDANCE · {label}"),
        state["message"]
            .as_str()
            .unwrap_or("Guidance origin is unavailable. No current goal is substituted.")
            .into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn saved_text_is_separate_from_claims_and_unknown_states_do_not_invent_a_goal() {
        let state = json!({"status":"recorded","reference":{"briefId":"repository","revision":1},"textBytes":8,"text":"Old goal"});
        let lines = context_goal_lines(&state).join("\n");
        assert!(lines.contains("exact revision 1"));
        assert!(lines.contains("Old goal"));
        assert!(lines.contains("Model use is not independently verified"));
        assert!(context_goal_lines(&json!({"status":"absent"})).is_empty());
        let missing = context_goal_lines(
            &json!({"status":"unavailable","message":"Missing immutable goal object"}),
        )
        .join("\n");
        assert!(missing.contains("unavailable"));
        assert!(!missing.contains("Old goal"));
    }

    #[test]
    fn explicit_omission_and_unbound_history_do_not_claim_a_missing_object() {
        for (status, label) in [
            ("omitted", "context explicitly omitted"),
            ("unbound", "historical context not bound"),
        ] {
            let lines = context_goal_lines(
                &json!({"status":status,"message":"No current context was inspected."}),
            )
            .join("\n");
            assert!(lines.contains(label));
            assert!(!lines.contains("· unavailable"));
            assert!(!lines.contains("Saved goal reference authenticated"));
        }
    }
}
