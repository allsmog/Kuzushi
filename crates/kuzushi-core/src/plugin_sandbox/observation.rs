use super::{
    GrantedSnapshot, PluginObservationContext, UntrustedFindingCandidate, ValidatedFindingCandidate,
};
use crate::identity::hash_parts;
use crate::storage_v3::writer_actor::CandidateObservationWrite;
use anyhow::{bail, Context, Result};

pub(super) fn candidate_observation_write(
    finding: ValidatedFindingCandidate,
    context: &PluginObservationContext,
    grant: &GrantedSnapshot,
) -> Result<CandidateObservationWrite> {
    let candidate = finding.into_inner();
    let span = source_span(&candidate, grant)?;
    let raw_result_json = serde_json::to_string(&serde_json::json!({
        "ruleId": &candidate.rule_id,
        "title": &candidate.title,
        "severity": &candidate.severity,
        "blobHash": &candidate.blob_hash,
        "byteStart": candidate.byte_start,
        "byteEnd": candidate.byte_end,
        "message": &candidate.message,
    }))?;
    Ok(CandidateObservationWrite {
        snapshot_hash: context.snapshot_hash.clone(),
        run_id: context.run_id.clone(),
        tool: context.tool.clone(),
        tool_version: context.tool_version.clone(),
        rule_id: candidate.rule_id,
        rule_set_hash: context.rule_set_hash.clone(),
        severity: candidate.severity,
        title: candidate.title,
        message: candidate.message,
        blob_hash: candidate.blob_hash.as_str().to_string(),
        byte_start: candidate.byte_start,
        byte_end: candidate.byte_end,
        display_path: context.display_paths.get(&candidate.blob_hash).cloned(),
        display_line: Some(span.display_line),
        language: context.languages.get(&candidate.blob_hash).cloned(),
        normalized_snippet: span.snippet,
        local_context_hash: Some(span.context_hash),
        raw_result_json,
        actor: context.actor.clone(),
    })
}

struct SourceSpanIdentity {
    snippet: String,
    context_hash: String,
    display_line: u32,
}

fn source_span(
    candidate: &UntrustedFindingCandidate,
    grant: &GrantedSnapshot,
) -> Result<SourceSpanIdentity> {
    let path = grant.object_path(&candidate.blob_hash).with_context(|| {
        format!(
            "plugin finding {} requires a CAS object path",
            candidate.rule_id
        )
    })?;
    // CAS ingestion already caps objects at this size; re-applying the cap
    // here keeps a tampered store object from exhausting memory.
    let bytes = crate::bounded_file::read_regular_bytes(
        path,
        crate::content_store::MAX_CONTENT_OBJECT_BYTES as usize,
    )
    .with_context(|| format!("Could not read granted blob object {}", path.display()))?;
    let start = usize::try_from(candidate.byte_start).context("plugin byte_start is too large")?;
    let end = usize::try_from(candidate.byte_end).context("plugin byte_end is too large")?;
    if start >= end || end > bytes.len() {
        bail!("plugin finding byte span no longer matches the granted object");
    }
    let snippet = snippet_identity(&bytes[start..end], candidate);
    Ok(SourceSpanIdentity {
        snippet,
        context_hash: span_context_hash(&bytes, start, end),
        display_line: display_line_for_offset(&bytes, start),
    })
}

fn snippet_identity(span: &[u8], candidate: &UntrustedFindingCandidate) -> String {
    let snippet = String::from_utf8_lossy(span).trim().to_string();
    if snippet.is_empty() {
        format!(
            "{}:{}..{}:{}",
            candidate.blob_hash.as_str(),
            candidate.byte_start,
            candidate.byte_end,
            candidate.message.trim()
        )
    } else {
        snippet
    }
}

fn span_context_hash(bytes: &[u8], start: usize, end: usize) -> String {
    let context_start = start.saturating_sub(128);
    let context_end = (end + 128).min(bytes.len());
    hash_parts("plugin-span-context", &[&bytes[context_start..context_end]])
        .as_str()
        .to_string()
}

fn display_line_for_offset(bytes: &[u8], offset: usize) -> u32 {
    bytes[..offset]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count()
        .saturating_add(1)
        .try_into()
        .unwrap_or(u32::MAX)
}
