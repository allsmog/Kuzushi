//! Quote edge whitespace and controls without changing stored membership.
pub(super) fn display_path(path: &str) -> String {
    if path.trim() == path && !path.chars().any(char::is_control) {
        return path.into();
    }
    serde_json::to_string(path).expect("a path string is serializable")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_path_display_distinguishes_edge_spaces_from_other_members() {
        assert_eq!(display_path("app"), "app");
        assert_eq!(display_path(" app "), "\" app \"");
        assert_eq!(display_path(" app /lib.py"), "\" app /lib.py\"");
        assert_eq!(display_path("app/a b.py"), "app/a b.py");
        assert_eq!(display_path(" app\" "), "\" app\\\" \"");
    }

    #[test]
    fn control_characters_in_literal_paths_are_quoted_instead_of_creating_rows() {
        assert_eq!(
            display_path("app/line\nroute.py"),
            "\"app/line\\nroute.py\""
        );
        assert_eq!(
            display_path("app/session\ttoken.py"),
            "\"app/session\\ttoken.py\""
        );
        assert_eq!(
            display_path("app/session  token.py"),
            "app/session  token.py"
        );
    }
}
