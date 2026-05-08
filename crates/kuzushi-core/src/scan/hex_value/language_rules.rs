use super::*;

pub(in crate::scan) struct CodeqlLanguageRule {
    language: &'static str,
    contains: &'static [&'static str],
    exact: &'static [&'static str],
}

pub(in crate::scan) const CODEQL_LANGUAGE_RULES: &[CodeqlLanguageRule] = &[
    CodeqlLanguageRule {
        language: "javascript",
        contains: &["javascript", "typescript"],
        exact: &[],
    },
    CodeqlLanguageRule {
        language: "python",
        contains: &["python"],
        exact: &[],
    },
    CodeqlLanguageRule {
        language: "csharp",
        contains: &["csharp"],
        exact: &["c#"],
    },
    CodeqlLanguageRule {
        language: "java",
        contains: &["java"],
        exact: &[],
    },
    CodeqlLanguageRule {
        language: "go",
        contains: &["go"],
        exact: &[],
    },
    CodeqlLanguageRule {
        language: "cpp",
        contains: &["cpp", "c-cpp"],
        exact: &["c++"],
    },
    CodeqlLanguageRule {
        language: "swift",
        contains: &["swift"],
        exact: &[],
    },
    CodeqlLanguageRule {
        language: "ruby",
        contains: &["ruby"],
        exact: &[],
    },
    CodeqlLanguageRule {
        language: "rust",
        contains: &["rust"],
        exact: &[],
    },
];

pub(in crate::scan) fn codeql_language_rule_for(value: &str) -> Option<&'static str> {
    CODEQL_LANGUAGE_RULES
        .iter()
        .find(|rule| codeql_language_rule_matches(rule, value))
        .map(|rule| rule.language)
}

pub(in crate::scan) fn codeql_language_rule_matches(
    rule: &CodeqlLanguageRule,
    value: &str,
) -> bool {
    rule.exact.iter().any(|exact| exact == &value)
        || rule.contains.iter().any(|needle| value.contains(needle))
}

pub(in crate::scan) fn is_compiled_codeql_language(language: &str) -> bool {
    matches!(
        language,
        "go" | "java" | "cpp" | "csharp" | "swift" | "rust"
    )
}
