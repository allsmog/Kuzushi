use super::prelude::*;
use super::*;

pub(crate) fn validate_citation_snippet(
    span: &SourceSpan,
    citation: &StaticProofCitation,
) -> Result<()> {
    if let Some(expected_hash) = citation.snippet_hash.as_deref() {
        if expected_hash != span.content_hash {
            anyhow::bail!(
                "snippet hash mismatch: expected {expected_hash}, found {}",
                span.content_hash
            );
        }
    }
    if let Some(expected_snippet) = citation.snippet.as_deref() {
        if normalize_snippet(expected_snippet) != normalize_snippet(&span.snippet) {
            anyhow::bail!("snippet text does not match cited source lines");
        }
    }
    Ok(())
}
