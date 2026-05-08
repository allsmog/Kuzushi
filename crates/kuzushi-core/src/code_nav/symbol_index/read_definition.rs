use super::prelude::*;
use super::*;

pub(super) fn is_ident(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !s.chars().next().is_some_and(|c| c.is_ascii_digit())
}

pub(super) fn keyword_at_start(token: &str) -> bool {
    matches!(
        token,
        "if" | "for" | "while" | "switch" | "return" | "case" | "do" | "else"
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadDefinitionInput {
    pub name: String,
    /// Optional file hint to scope the search.
    #[serde(default)]
    pub hint_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadDefinitionOutput {
    pub name: String,
    pub file: String,
    pub line: u32,
    pub kind: String,
    pub signature: String,
    pub source: String,
    /// Other candidate locations the heuristic found, in case the first
    /// pick is wrong.
    pub also_seen: Vec<DefinitionEntry>,
}

/// Best-effort `read_definition`: find the symbol via `find_references`,
/// pick the line that looks like a definition (signature ending with `{`
/// or `:`), then read a window around it.
pub fn read_definition(root: &Path, input: &ReadDefinitionInput) -> Result<ReadDefinitionOutput> {
    let symbol = input.name.trim();
    anyhow::ensure!(
        !symbol.is_empty(),
        "read_definition: name must be non-empty"
    );

    let refs = find_references(
        root,
        &FindReferencesInput {
            symbol: symbol.to_string(),
            scope: input.hint_file.clone(),
            language: None,
        },
    )?;

    let mut candidates: Vec<DefinitionEntry> = refs
        .hits
        .into_iter()
        .filter_map(|hit| {
            classify_hit(&hit.snippet, symbol)
                .map(|kind| DefinitionEntry {
                    name: symbol.to_string(),
                    kind,
                    line: hit.line,
                    signature: hit.snippet.clone(),
                })
                .map(|entry| (hit.file, entry))
        })
        .map(|(file, mut entry)| {
            entry.signature = format!("{}:{}\t{}", file, entry.line, entry.signature);
            (file, entry)
        })
        .map(|(_file, e)| e)
        .collect();

    let primary = candidates
        .pop()
        .ok_or_else(|| anyhow::anyhow!("read_definition: no definition for {symbol:?}"))?;

    // The signature was decorated with file:line — split it back so we can
    // find the file and read a window.
    let (file_line_marker, signature) = primary
        .signature
        .split_once('\t')
        .unwrap_or(("", primary.signature.as_str()));
    let (file, _line_str) = file_line_marker
        .split_once(':')
        .unwrap_or(("", file_line_marker));
    let source_window = read_source(
        root,
        &ReadSourceInput {
            file: file.to_string(),
            start_line: Some(primary.line.saturating_sub(2).max(1)),
            end_line: Some(primary.line + 30),
        },
    )?;

    Ok(ReadDefinitionOutput {
        name: symbol.to_string(),
        file: file.to_string(),
        line: primary.line,
        kind: primary.kind,
        signature: signature.to_string(),
        source: source_window.contents,
        also_seen: candidates,
    })
}

pub(super) fn classify_hit(snippet: &str, symbol: &str) -> Option<String> {
    let t = snippet.trim_start();
    if !contains_symbol_call(t, symbol) {
        return classify_type_hit(t, symbol);
    }
    classify_callable_hit(t)
}

pub(super) fn contains_symbol_call(snippet: &str, symbol: &str) -> bool {
    let compact = format!("{symbol}(");
    let spaced = format!("{symbol} (");
    snippet.contains(&compact) || snippet.contains(&spaced)
}

pub(super) fn classify_type_hit(snippet: &str, symbol: &str) -> Option<String> {
    ["struct ", "enum ", "trait ", "class ", "type "]
        .iter()
        .any(|keyword| symbol_follows_keyword(snippet, keyword, symbol))
        .then(|| "struct".to_string())
}

pub(super) fn symbol_follows_keyword(snippet: &str, keyword: &str, symbol: &str) -> bool {
    snippet
        .strip_prefix(keyword)
        .map(str::trim_start)
        .is_some_and(|rest| rest.starts_with(symbol))
}

pub(super) fn classify_callable_hit(snippet: &str) -> Option<String> {
    [
        is_rust_function_signature(snippet),
        is_python_function_signature(snippet),
        snippet.starts_with("func "),
        is_c_like_function_signature(snippet),
    ]
    .into_iter()
    .any(|matched| matched)
    .then(|| "function".to_string())
}

pub(super) fn is_rust_function_signature(snippet: &str) -> bool {
    ["fn ", "pub fn ", "async fn ", "pub async fn "]
        .iter()
        .any(|prefix| snippet.starts_with(prefix))
}

pub(super) fn is_python_function_signature(snippet: &str) -> bool {
    ["def ", "async def "]
        .iter()
        .any(|prefix| snippet.starts_with(prefix))
}

pub(super) fn is_c_like_function_signature(snippet: &str) -> bool {
    snippet.contains(") {") || snippet.ends_with(')')
}
