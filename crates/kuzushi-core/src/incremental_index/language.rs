use std::path::Path;

pub(super) fn language_for_path(path: &Path) -> Option<String> {
    let extension = path.extension()?.to_str()?;
    let language = match extension {
        "rs" => "rust",
        "go" => "go",
        "js" | "mjs" | "cjs" => "javascript",
        "ts" | "tsx" => "typescript",
        "py" => "python",
        "java" => "java",
        "kt" | "kts" => "kotlin",
        "rb" => "ruby",
        "php" => "php",
        "cs" => "csharp",
        "c" | "h" => "c",
        "cc" | "cpp" | "cxx" | "hpp" | "hh" => "cpp",
        "swift" => "swift",
        "json" => "json",
        "yaml" | "yml" => "yaml",
        "toml" => "toml",
        _ => return None,
    };
    Some(language.to_string())
}
