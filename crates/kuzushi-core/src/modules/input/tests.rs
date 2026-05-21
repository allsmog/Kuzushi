#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::options::looks_like_prompt_path;
    use serde_json::json;

    #[test]
    fn positive_f64_input_accepts_numbers_and_strings_and_rejects_bad_values() {
        assert_eq!(
            positive_f64_input(&json!({"cap": 1.5}), &["cap"], "cap")
                .unwrap()
                .unwrap(),
            1.5
        );
        assert_eq!(
            positive_f64_input(&json!({"cap_text": "2.75"}), &["cap", "cap_text"], "cap")
                .unwrap()
                .unwrap(),
            2.75
        );
        assert!(positive_f64_input(&json!({}), &["cap"], "cap")
            .unwrap()
            .is_none());

        for input in [
            json!({"cap": 0.0}),
            json!({"cap": -1.0}),
            json!({"cap": "NaN"}),
            json!({"cap": true}),
        ] {
            assert!(positive_f64_input(&input, &["cap"], "cap").is_err());
        }
    }

    #[test]
    fn prompt_path_detection_covers_relative_absolute_and_plain_text() {
        assert!(looks_like_prompt_path("./prompt.md"));
        assert!(looks_like_prompt_path("../prompt.txt"));
        assert!(looks_like_prompt_path("/tmp/prompt.prompt"));
        assert!(looks_like_prompt_path("checked-in.md"));
        assert!(!looks_like_prompt_path("inline prompt text"));
    }

    #[test]
    fn parse_sast_tasks_keeps_cargo_audit_when_auto_tasks_are_filtered() {
        let tasks = parse_sast_tasks(&json!({"disabledTasks": ["semgrep"]})).unwrap();

        assert!(tasks.iter().any(|task| task == "cargo-audit"));
        assert!(!tasks.iter().any(|task| task == "semgrep"));
    }
}
