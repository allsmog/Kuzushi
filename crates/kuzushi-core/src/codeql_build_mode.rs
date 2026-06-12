use anyhow::Result;

const DEFAULT_BUILD_MODE: &str = "default";
const AUTOBUILD_MODE: &str = "autobuild";
const NONE_MODE: &str = "none";

pub(crate) fn codeql_build_mode_plan(
    language: &str,
    explicit_mode: Option<&str>,
) -> Result<Vec<String>> {
    if let Some(mode) = explicit_mode.and_then(non_empty_trimmed) {
        return Ok(vec![normalize_codeql_build_mode(mode)?]);
    }
    if uses_autobuild_only(language) {
        return Ok(vec![AUTOBUILD_MODE.to_string()]);
    }
    if is_compiled_codeql_language(language) {
        return Ok(vec![AUTOBUILD_MODE.to_string(), NONE_MODE.to_string()]);
    }
    Ok(vec![DEFAULT_BUILD_MODE.to_string()])
}

pub(crate) fn normalize_codeql_build_mode(raw: &str) -> Result<String> {
    let mode = raw.trim().to_lowercase();
    match mode.as_str() {
        DEFAULT_BUILD_MODE | AUTOBUILD_MODE | NONE_MODE => Ok(mode),
        _ => {
            anyhow::bail!("codeql: buildMode must be one of default, autobuild, none; got {raw:?}")
        }
    }
}

pub(crate) fn is_compiled_codeql_language(language: &str) -> bool {
    matches!(
        normalized_codeql_language(language).as_str(),
        "go" | "java"
            | "kotlin"
            | "java-kotlin"
            | "cpp"
            | "c"
            | "c-cpp"
            | "csharp"
            | "rust"
            | "swift"
    )
}

fn uses_autobuild_only(language: &str) -> bool {
    normalized_codeql_language(language) == "swift"
}

fn normalized_codeql_language(language: &str) -> String {
    language.trim().to_lowercase()
}

fn non_empty_trimmed(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then_some(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_languages_default_to_autobuild_then_none() {
        assert_eq!(
            codeql_build_mode_plan("cpp", None).unwrap(),
            vec!["autobuild".to_string(), "none".to_string()]
        );
        assert_eq!(
            codeql_build_mode_plan(" JAVA ", None).unwrap(),
            vec!["autobuild".to_string(), "none".to_string()]
        );
    }

    #[test]
    fn swift_defaults_to_autobuild_only() {
        assert_eq!(
            codeql_build_mode_plan("swift", None).unwrap(),
            vec!["autobuild".to_string()]
        );
    }

    #[test]
    fn interpreted_languages_use_default_create_behavior() {
        assert_eq!(
            codeql_build_mode_plan("javascript", None).unwrap(),
            vec!["default".to_string()]
        );
    }

    #[test]
    fn explicit_mode_is_validated_and_used_alone() {
        assert_eq!(
            codeql_build_mode_plan("cpp", Some(" NONE ")).unwrap(),
            vec!["none".to_string()]
        );
        assert!(codeql_build_mode_plan("cpp", Some("fast")).is_err());
    }
}
