//! Approval and Report present the same frozen selector; details retain its stored identity.
pub(super) fn discovery_model_line(model: Option<&str>, workers: usize) -> String {
    let label = match model {
        Some(model) if model.trim().is_empty() => "unrecorded".into(),
        Some(model) => crate::app::display_model_selector(model),
        None => "none recorded for discovery".into(),
    };
    format!("Model: {label} · {workers} worker(s)")
}

pub(super) fn recorded_model_line(model: Option<&str>) -> Option<String> {
    model.map(|model| format!("Recorded model identity: {model}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_matches_approval_without_changing_the_recorded_model() {
        for (recorded, displayed) in [
            ("openai-codex:gpt-5.5", "openai-oauth:gpt-5.5"),
            ("openai:gpt-5.5", "openai:gpt-5.5"),
            ("anthropic:owned-model", "anthropic:owned-model"),
            ("owned:unknown-model", "owned:unknown-model"),
        ] {
            assert_eq!(
                discovery_model_line(Some(recorded), 2),
                format!("Model: {displayed} · 2 worker(s)")
            );
            assert_eq!(
                recorded_model_line(Some(recorded)),
                Some(format!("Recorded model identity: {recorded}"))
            );
        }
    }

    #[test]
    fn missing_and_empty_models_never_select_a_model_or_look_equivalent() {
        assert_eq!(
            discovery_model_line(None, 1),
            "Model: none recorded for discovery · 1 worker(s)"
        );
        assert_eq!(
            discovery_model_line(Some(" "), 1),
            "Model: unrecorded · 1 worker(s)"
        );
        assert!(recorded_model_line(None).is_none());
    }
}
