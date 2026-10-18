//! Quoting distinguishes literal edge spaces without changing stored membership.
pub(super) fn display_path(path: &str) -> String {
    if path.trim() == path {
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
}
