use super::*;

pub(in crate::capabilities::taint_iris_next) fn deterministic_taint_iris_next_fallback(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
) -> (Vec<Finding>, Vec<Value>, Vec<Value>) {
    if !taint_iris_next_evidence_meets_minimum("linked", &plan.caps.min_evidence_level) {
        return (Vec::new(), Vec::new(), Vec::new());
    }
    let candidates = evidence
        .candidates
        .iter()
        .map(|candidate| (candidate.id.clone(), candidate))
        .collect::<BTreeMap<_, _>>();
    let mut findings = Vec::new();
    let mut selections_by_cwe = BTreeMap::new();
    let mut triage = Vec::new();
    for story in evidence
        .linked_stories
        .iter()
        .take(plan.caps.max_agent_findings)
    {
        let Some(source) = candidates.get(&story.source_candidate_id) else {
            continue;
        };
        let Some(sink) = candidates.get(&story.sink_candidate_id) else {
            continue;
        };
        selections_by_cwe.entry(story.cwe.clone()).or_insert_with(|| {
            json!({
                "cwe": story.cwe,
                "reason": "Deterministic structural linker produced linked evidence before agent selection completed.",
                "catalogSignals": [source.catalog_signal.clone(), sink.catalog_signal.clone()],
                "sourceSpec": source.catalog_signal,
                "sinkSpec": sink.catalog_signal,
                "sanitizerSpec": "",
                "customCweRationale": "",
                "knownCatalogCwe": true,
            })
        });
        triage.push(json!({
            "status": "finding",
            "cwe": story.cwe,
            "evidenceLevel": "linked",
            "rationale": format!("Deterministic fallback: {}", story.rationale),
            "filePath": story.file_path,
            "line": story.sink_line,
            "catalogSignals": [source.catalog_signal.clone(), sink.catalog_signal.clone()],
        }));
        let message = format!(
            "[{}] Linked {} candidate: {}. Agent triage output was unavailable or invalid, so review before treating as confirmed.\nTaint path:\n- {}:{}: source: {} | {}\n- {}:{}: sink: {} | {}",
            story.cwe,
            story.taint_class,
            story.rationale,
            source.file_path,
            source.line,
            source.catalog_signal,
            source.snippet,
            sink.file_path,
            sink.line,
            sink.catalog_signal,
            sink.snippet
        );
        findings.push(Finding::new_tool(
            "taint-iris-next",
            format!("taint-iris-next/{}", sanitize_rule_segment(&story.cwe)),
            story.file_path.clone(),
            story.sink_line,
            None,
            deterministic_taint_iris_next_severity(&story.cwe),
            message,
        ));
    }
    (findings, selections_by_cwe.into_values().collect(), triage)
}
