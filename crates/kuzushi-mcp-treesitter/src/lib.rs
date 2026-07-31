//! Shared language-set contract for the tree-sitter MCP server.
//! Single source of truth consumed by tools.rs grammar_for, callers_pattern_table,
//! the node_at schema description, the unsupported-language error, and `kuzushi doctor`.
//! Adding a language here without BOTH a grammar_for arm and a callers_pattern_table
//! entry is a test failure — see every_supported_language_has_a_compiling_grammar_and_caller_pattern.

/// Every language id `tree_sitter:*` accepts, alphabetically.
pub const SUPPORTED_LANGUAGES: &[&str] = &[
    "c",
    "cpp",
    "go",
    "java",
    "javascript",
    "php",
    "python",
    "ruby",
    "rust",
    "typescript",
];

/// Comma-separated rendering used by the tool schemas, error message, and doctor row.
pub fn supported_language_list() -> String {
    SUPPORTED_LANGUAGES.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn supported_languages_are_sorted_deduped_and_nonempty() {
        assert!(!SUPPORTED_LANGUAGES.is_empty());
        let mut s = SUPPORTED_LANGUAGES.to_vec();
        s.sort_unstable();
        s.dedup();
        assert_eq!(s.as_slice(), SUPPORTED_LANGUAGES);
    }
    #[test]
    fn language_list_names_cpp_and_rust() {
        let l = supported_language_list();
        assert!(l.contains("cpp"), "{l}");
        assert!(l.contains("rust"), "{l}");
    }
}
