use super::hash_parts;

const DEFAULT_PARSER_VERSION: &str = "none";
const DEFAULT_NORMALIZER_VERSION: &str = "kuzushi-normalizer-v3";

#[derive(Debug, Clone)]
pub struct StableFindingInput<'a> {
    pub tool_family: &'a str,
    pub rule_id: &'a str,
    pub language: Option<&'a str>,
    pub parser_version: Option<&'a str>,
    pub normalizer_version: Option<&'a str>,
    pub symbol_path_or_rename_group: Option<&'a str>,
    pub ast_locus_hash: Option<&'a str>,
    pub normalized_snippet: &'a str,
    pub local_context_hash: Option<&'a str>,
    pub disambiguator: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct ObservationHashInput<'a> {
    pub run_id: &'a str,
    pub tool_name: &'a str,
    pub tool_version: Option<&'a str>,
    pub rule_set_hash: Option<&'a str>,
    pub snapshot_hash: Option<&'a str>,
    pub raw_result_hash: &'a str,
}

pub fn compute_stable_fp_v3(input: StableFindingInput<'_>) -> String {
    let language = normalized_optional(input.language);
    let parser_version = normalized_or(input.parser_version, DEFAULT_PARSER_VERSION);
    let normalizer_version = normalized_or(input.normalizer_version, DEFAULT_NORMALIZER_VERSION);
    let symbol = normalized_optional(input.symbol_path_or_rename_group);
    let ast_locus = normalized_optional(input.ast_locus_hash);
    let snippet = normalize_finding_text(input.normalized_snippet);
    let context = normalized_optional(input.local_context_hash);
    let disambiguator = normalized_optional(input.disambiguator);
    let hash = hash_parts(
        "finding",
        &[
            b"identity-version:3",
            normalize_token(input.tool_family).as_bytes(),
            normalize_token(input.rule_id).as_bytes(),
            language.as_bytes(),
            parser_version.as_bytes(),
            normalizer_version.as_bytes(),
            symbol.as_bytes(),
            ast_locus.as_bytes(),
            snippet.as_bytes(),
            context.as_bytes(),
            disambiguator.as_bytes(),
        ],
    );
    format!("fp3_{}", hash.as_str())
}

pub fn stable_fingerprint_for_tool(
    tool: &str,
    rule_id: &str,
    file_path: &str,
    _title: &str,
    _message: &str,
) -> String {
    tool_fingerprint(tool, rule_id, file_path, None)
}

/// Producer fingerprint for tools whose rule and file alone do not name one
/// issue, such as two dependencies in one manifest or two blocks in one IaC
/// file. The discriminator is producer-owned structure (or an exact
/// statement position) and never producer prose, so rewording a message still
/// cannot split an issue while distinct issues no longer share one row.
pub fn discriminated_fingerprint_for_tool(
    tool: &str,
    rule_id: &str,
    file_path: &str,
    discriminator: &str,
) -> String {
    tool_fingerprint(tool, rule_id, file_path, Some(discriminator))
}

fn tool_fingerprint(
    tool: &str,
    rule_id: &str,
    file_path: &str,
    disambiguator: Option<&str>,
) -> String {
    let identity_hint = normalize_finding_text(rule_id);
    compute_stable_fp_v3(StableFindingInput {
        tool_family: tool,
        rule_id,
        language: None,
        parser_version: None,
        normalizer_version: None,
        symbol_path_or_rename_group: Some(&normalize_path(file_path)),
        ast_locus_hash: None,
        normalized_snippet: &identity_hint,
        local_context_hash: None,
        disambiguator,
    })
}

pub fn compute_observation_hash_v3(input: ObservationHashInput<'_>) -> String {
    let tool_version = normalized_optional(input.tool_version);
    let rule_set_hash = normalized_optional(input.rule_set_hash);
    let snapshot_hash = normalized_optional(input.snapshot_hash);
    let hash = hash_parts(
        "observation",
        &[
            b"identity-version:3",
            input.run_id.trim().as_bytes(),
            input.tool_name.trim().as_bytes(),
            tool_version.as_bytes(),
            rule_set_hash.as_bytes(),
            snapshot_hash.as_bytes(),
            input.raw_result_hash.trim().as_bytes(),
        ],
    );
    format!("obs3_{}", hash.as_str())
}

pub(crate) fn normalize_finding_text(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(crate) fn normalize_path(path: &str) -> String {
    path.trim().replace('\\', "/").trim_start_matches("./").to_string()
}

pub(crate) fn normalize_token(value: &str) -> String {
    normalize_finding_text(value)
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn normalized_optional(value: Option<&str>) -> String {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("none")
        .to_string()
}

fn normalized_or(value: Option<&str>, fallback: &str) -> String {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(snippet: &str) -> StableFindingInput<'_> {
        StableFindingInput {
            tool_family: "semgrep",
            rule_id: "CWE-89/raw-sql",
            language: Some("rust"),
            parser_version: Some("tree-sitter-rust@1"),
            normalizer_version: Some("test-normalizer"),
            symbol_path_or_rename_group: Some("crate::db::search"),
            ast_locus_hash: Some("call/db-query"),
            normalized_snippet: snippet,
            local_context_hash: Some("parent-if"),
            disambiguator: None,
        }
    }

    #[test]
    fn stable_finding_id_ignores_line_numbers_by_construction() {
        let first = stable_fingerprint_for_tool("semgrep", "CWE-89", "src/db.rs", "SQLi", "raw query");
        let second = stable_fingerprint_for_tool("semgrep", "CWE-89", "src/db.rs", "SQLi", "raw query");

        assert_eq!(first, second);
        assert!(first.starts_with("fp3_"));
    }

    #[test]
    fn discriminated_fingerprint_separates_issues_sharing_rule_and_file() {
        let base = stable_fingerprint_for_tool("dep-hygiene", "dep-hygiene/package-json", "package.json", "", "");
        let first = discriminated_fingerprint_for_tool(
            "dep-hygiene",
            "dep-hygiene/package-json",
            "package.json",
            "package.json#left-pad",
        );
        let second = discriminated_fingerprint_for_tool(
            "dep-hygiene",
            "dep-hygiene/package-json",
            "package.json",
            "package.json#right-pad",
        );

        assert_ne!(first, second);
        assert_ne!(first, base);
        assert_eq!(
            first,
            discriminated_fingerprint_for_tool(
                "dep-hygiene",
                "dep-hygiene/package-json",
                "package.json",
                "package.json#left-pad",
            )
        );
    }

    #[test]
    fn stable_finding_id_changes_with_rule_id() {
        let first = compute_stable_fp_v3(input("db.query(user_input)"));
        let mut changed = input("db.query(user_input)");
        changed.rule_id = "CWE-79/html";

        assert_ne!(first, compute_stable_fp_v3(changed));
    }

    #[test]
    fn observation_hash_changes_with_run_id() {
        let first = compute_observation_hash_v3(ObservationHashInput {
            run_id: "run-a",
            tool_name: "semgrep",
            tool_version: Some("1"),
            rule_set_hash: Some("rules"),
            snapshot_hash: Some("snapshot"),
            raw_result_hash: "raw",
        });
        let second = compute_observation_hash_v3(ObservationHashInput {
            run_id: "run-b",
            tool_name: "semgrep",
            tool_version: Some("1"),
            rule_set_hash: Some("rules"),
            snapshot_hash: Some("snapshot"),
            raw_result_hash: "raw",
        });

        assert_ne!(first, second);
    }
}
