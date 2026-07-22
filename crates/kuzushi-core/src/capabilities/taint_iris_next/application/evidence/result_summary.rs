use super::*;

pub(super) fn linked_story_ids_by_candidate(
    linked_stories: &[TaintIrisNextLinkedStory],
) -> BTreeMap<String, String> {
    linked_stories
        .iter()
        .flat_map(|story| {
            [
                (story.source_candidate_id.clone(), story.id.clone()),
                (story.sink_candidate_id.clone(), story.id.clone()),
            ]
        })
        .collect()
}

pub(super) fn count_labeled_specs(
    labeled_specs: &[TaintIrisNextLabeledSpec],
) -> BTreeMap<String, usize> {
    labeled_specs
        .iter()
        .fold(BTreeMap::new(), |mut counts, spec| {
            *counts.entry(spec.cwe.clone()).or_insert(0) += 1;
            counts
        })
}

pub(super) fn selected_tool(plan: &TaintIrisNextPlan) -> String {
    match plan.backend.selected.as_str() {
        "codeql" => "codeql".to_string(),
        "cpg-rs" => "cpg-rs".to_string(),
        _ => plan.backend.structural_tool.clone(),
    }
}

pub(super) fn outcome(linked_story_count: usize, candidate_count: usize) -> &'static str {
    if linked_story_count > 0 {
        "linked-evidence"
    } else if candidate_count > 0 {
        "candidate-only"
    } else {
        "structural-only"
    }
}
