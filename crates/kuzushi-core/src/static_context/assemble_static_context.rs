use super::*;

pub const SUBGRAPH_LINE_WINDOW: u32 = 30;

pub const SUBGRAPH_NODE_CAP: usize = 20;

#[derive(Debug, Clone)]
pub struct StaticContextSources<'a> {
    /// Workspace root for opening the static-evidence DB.
    pub workspace_root: &'a Path,
    /// Optional explicit language hint (lowercase, e.g. "c", "rust").
    /// When `None`, the assembler infers from `finding.file_path`.
    pub language: Option<&'a str>,
    /// Optional symbol seed for registry matching (e.g. the function
    /// name from the finding's title). When `None`, registry matches
    /// fall back to text-based lookup.
    pub symbol_hint: Option<&'a str>,
    /// Optional snippet of the surrounding source for text-based registry
    /// matching. When `None`, registry matches fall back to symbol hints.
    pub source_snippet: Option<&'a str>,
}

impl<'a> StaticContextSources<'a> {
    pub fn new(workspace_root: &'a Path) -> Self {
        Self {
            workspace_root,
            language: None,
            symbol_hint: None,
            source_snippet: None,
        }
    }
}

pub fn assemble_static_context(
    finding: &Finding,
    sources: &StaticContextSources<'_>,
) -> Option<String> {
    let language = sources
        .language
        .map(str::to_string)
        .unwrap_or_else(|| infer_language(&finding.file_path));

    // 1. Registry hits - deterministic, no DB.
    let registry_matches =
        match_registry_for(&language, sources.symbol_hint, sources.source_snippet);

    // 2. Narrative - always available, computed on demand.
    let narrative = derive_narrative(finding);

    // 3. Static-evidence subgraph slice - best-effort; store may be absent.
    let (nodes, edges) = load_subgraph_slice(finding, sources.workspace_root);

    // 4. Proof state + impact score from `Finding` + ranking.
    let proof_state = finding.static_proof_state;
    let impact = compute_impact_score(finding);

    // Fast-path: if nothing is known, skip injection entirely.
    let has_anything = narrative.is_some()
        || !registry_matches.is_empty()
        || !nodes.is_empty()
        || proof_state.is_some();
    if !has_anything {
        return None;
    }

    Some(render_markdown(
        narrative.as_ref(),
        &registry_matches,
        &nodes,
        &edges,
        proof_state,
        impact,
    ))
}

pub(crate) fn infer_language(path: &str) -> String {
    let extension = path
        .rsplit('.')
        .next()
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    static_context_language(&extension)
        .unwrap_or("unknown")
        .to_string()
}

fn static_context_language(extension: &str) -> Option<&'static str> {
    static_context_language_table()
        .iter()
        .find(|(extensions, _)| extensions.contains(&extension))
        .map(|(_, language)| *language)
}

fn static_context_language_table() -> &'static [(&'static [&'static str], &'static str)] {
    &[
        (&["c", "h"], "c"),
        (&["cc", "cpp", "cxx", "hh", "hpp", "hxx"], "cpp"),
        (&["rs"], "rust"),
        (&["go"], "go"),
        (&["py"], "python"),
        (&["java"], "java"),
        (&["js", "jsx", "mjs", "cjs", "ts", "tsx"], "TypeScript"),
    ]
}
