use super::*;

fn receipt(state: &str) -> LessonGeneration {
    LessonGeneration {
        model: "openai-codex:gpt-5.5".into(),
        source_capture: state.into(),
        input_bytes: 2048,
        synthesis_requests: 1,
        run_id: Some("recorded-lesson-run".into()),
        prompt_sha256: format!("sha256:{}", "a".repeat(64)),
    }
}

#[test]
fn generation_receipts_explain_supplied_and_omitted_source_at_every_width() {
    for (state, expected) in [
        ("included", "Captured historical source supplied."),
        ("not_recorded", "Source omitted: no capture was recorded."),
        (
            "unavailable_or_over_limit",
            "Source omitted: capture unavailable or over the byte limit.",
        ),
    ] {
        for width in [40, 60, 80, 96, 120, 160] {
            let text = receipt_lines(&receipt(state), width)
                .iter()
                .map(Line::to_string)
                .collect::<Vec<_>>()
                .join(" ");
            let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
            assert!(text.contains(expected), "{text}");
            assert!(text.contains("Evidence text: 2048 B · draft requests: 1"));
            assert!(text.contains("Provider retries also count toward the allowance."));
            assert!(!text.contains("model requests:"));
            assert!(text.contains("recorded-lesson-run"));
            assert!(!text.contains("Source supplied:"));
        }
    }
}

#[test]
fn unknown_capture_status_never_claims_that_source_was_supplied() {
    let lines = receipt_lines(&receipt("unknown"), 120);
    let text = lines
        .iter()
        .map(Line::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(text.contains("Source capture status unavailable."));
    assert!(!text.contains("historical source supplied"));
}
