use super::*;

pub(super) fn project_candidate_evidence(
    candidates: &[TaintIrisNextCandidate],
    linked_by_candidate: &BTreeMap<String, String>,
) -> Vec<TaintIrisNextEvidence> {
    candidates
        .iter()
        .map(|candidate| TaintIrisNextEvidence {
            cwe: candidate.cwe.clone(),
            taint_class: candidate.taint_class.clone(),
            track: candidate.track.clone(),
            role: candidate.role.clone(),
            pattern: candidate.pattern.clone(),
            file_path: candidate.file_path.clone(),
            line: candidate.line,
            snippet: candidate.snippet.clone(),
            language: candidate.language.clone(),
            confidence: candidate.confidence.clone(),
            catalog_signal: candidate.catalog_signal.clone(),
            evidence_level: linked_by_candidate
                .get(&candidate.id)
                .map(|_| "linked")
                .unwrap_or("candidate")
                .to_string(),
            source: candidate.source.clone(),
            candidate_id: candidate.id.clone(),
            linked_story_id: linked_by_candidate.get(&candidate.id).cloned(),
        })
        .collect()
}
