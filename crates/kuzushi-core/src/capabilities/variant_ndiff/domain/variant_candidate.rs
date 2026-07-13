use super::*;

pub(crate) fn variant_candidate_from_window(
    repo_root: &Path,
    pattern: &WhiteboxVariantPattern,
    relative_path: &str,
    line_no: u32,
    window: &str,
    line: &str,
) -> Option<Finding> {
    let lower = window.to_ascii_lowercase();
    let matched_sources = tokens_present(&lower, &pattern.source_tokens);
    let matched_sinks = tokens_present(&lower, &pattern.sink_tokens);
    if matched_sources.is_empty() || matched_sinks.is_empty() {
        return None;
    }
    let line_lower = line.to_ascii_lowercase();
    if tokens_present(&line_lower, &pattern.sink_tokens).is_empty() {
        return None;
    }
    let matched_guards = tokens_present(&lower, &pattern.missing_guard_tokens);
    if !matched_guards.is_empty() {
        return None;
    }

    let repo = repo_name(repo_root);
    let mut finding = Finding::new_tool(
        "whitebox-variant-search",
        format!("whitebox-variant/{}", pattern.rule_id),
        relative_path.to_string(),
        line_no,
        Some(line_no),
        Severity::Medium,
        format!(
            "Static variant candidate of {}. Matched source token(s) {} and sink token(s) {} without obvious guard token(s). Proof starts as code_cited and requires independent validation.\nEvidence: {}",
            pattern.rule_id,
            matched_sources.join(", "),
            matched_sinks.join(", "),
            line.trim()
        ),
    )
    .with_static_proof_state(StaticProofState::CodeCited);
    finding.fingerprint = stable_fingerprint(&[
        &repo,
        "whitebox-variant-search",
        &pattern.original_fingerprint,
        relative_path,
        &line_no.to_string(),
    ]);
    Some(finding)
}

pub(crate) fn variant_pattern_corpus(
    finding: &Finding,
    evidence_nodes: &[StaticEvidenceNode],
) -> String {
    let mut parts = vec![
        finding.rule_id.as_str(),
        finding.title.as_str(),
        finding.message.as_str(),
        finding.file_path.as_str(),
    ];
    let metadata = evidence_nodes
        .iter()
        .map(|node| node.metadata.to_string())
        .collect::<Vec<_>>();
    for node in evidence_nodes {
        parts.push(node.title.as_str());
        parts.push(node.body.as_str());
        if let Some(source_path) = node.source_path.as_deref() {
            parts.push(source_path);
        }
    }
    for item in &metadata {
        parts.push(item.as_str());
    }
    parts.join("\n").to_ascii_lowercase()
}

pub(crate) fn matching_tokens(corpus: &str, candidates: &[&str]) -> Vec<String> {
    candidates
        .iter()
        .filter(|token| corpus.contains(&token.to_ascii_lowercase()))
        .map(|token| (*token).to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(crate) fn tokens_present(corpus: &str, tokens: &[String]) -> Vec<String> {
    tokens
        .iter()
        .filter(|token| corpus.contains(&token.to_ascii_lowercase()))
        .cloned()
        .collect()
}
