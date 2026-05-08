#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn extracts_first_parseable_balanced_json_without_using_last_brace_in_prose() {
        let parsed =
            parse_json_value_from_agent_text("before {not json} then {\"ok\":true} after }")
                .unwrap();
        assert_eq!(parsed["ok"], true);
    }

    #[test]
    fn parses_json_fence() {
        let parsed = parse_json_value_from_agent_text("```json\n{\"ok\":true}\n```").unwrap();
        assert_eq!(parsed["ok"], true);
    }
}
