use super::*;

pub(in crate::modules::taint_iris_next) fn normalize_taint_next_language(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "js" | "javascript" => "javascript",
        "ts" | "typescript" => "typescript",
        "py" | "python" => "python",
        "rb" | "ruby" => "ruby",
        "rs" | "rust" => "rust",
        "golang" | "go" => "go",
        "c++" | "cpp" | "cxx" => "cpp",
        "c#" | "csharp" => "csharp",
        "java" => "java",
        "php" => "php",
        "c" => "c",
        "any" => "any",
        other => other,
    }
    .to_string()
}

pub(in crate::modules::taint_iris_next) fn normalize_taint_next_cwe(value: &str) -> String {
    let trimmed = value.trim().to_ascii_uppercase();
    let digits = trimmed
        .strip_prefix("CWE-")
        .or_else(|| trimmed.strip_prefix("CWE_"))
        .or_else(|| trimmed.strip_prefix("CWE "))
        .unwrap_or(&trimmed);
    if let Ok(number) = digits.parse::<u32>() {
        return format!("CWE-{number}");
    }
    trimmed
}

pub(in crate::modules::taint_iris_next) fn cwe_number(value: &str) -> u32 {
    normalize_taint_next_cwe(value)
        .strip_prefix("CWE-")
        .and_then(|digits| digits.parse::<u32>().ok())
        .unwrap_or(u32::MAX)
}
