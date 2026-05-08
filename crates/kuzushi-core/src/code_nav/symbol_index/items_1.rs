use super::prelude::*;
use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDefinitionsInput {
    pub file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefinitionEntry {
    pub name: String,
    pub kind: String, // "function" | "struct" | "enum" | "method" | "macro"
    pub line: u32,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDefinitionsOutput {
    pub file: String,
    pub language: String,
    pub definitions: Vec<DefinitionEntry>,
}

pub fn list_definitions(
    root: &Path,
    input: &ListDefinitionsInput,
) -> Result<ListDefinitionsOutput> {
    let canonical = canonicalise_within(root, &input.file)
        .with_context(|| format!("list_definitions: path {:?}", input.file))?;
    let body = fs::read_to_string(&canonical)
        .with_context(|| format!("list_definitions: could not read {}", input.file))?;

    let language = detect_language(&input.file);
    let definitions = match language.as_str() {
        "c" | "cpp" => scan_c_like(&body),
        "rust" => scan_rust(&body),
        "go" => scan_go(&body),
        "python" => scan_python(&body),
        "java" => scan_java(&body),
        _ => Vec::new(),
    };

    Ok(ListDefinitionsOutput {
        file: input.file.clone(),
        language,
        definitions,
    })
}

pub(in crate::code_nav) fn detect_language(path: &str) -> String {
    let ext = path
        .rsplit('.')
        .next()
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    match ext.as_str() {
        "c" | "h" => "c".to_string(),
        "cc" | "cpp" | "cxx" | "hh" | "hpp" | "hxx" => "cpp".to_string(),
        "rs" => "rust".to_string(),
        "go" => "go".to_string(),
        "py" => "python".to_string(),
        "java" => "java".to_string(),
        _ => "unknown".to_string(),
    }
}
