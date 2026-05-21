use super::agent_dispatch::agent_question_with_failure_context;
use kuzushi_core::run_artifacts::{FailureToLlmContext, RunArtifact};

#[test]
fn failure_context_is_injected_into_agent_prompt_without_replacing_question() {
    let context = FailureToLlmContext {
        failed_stage: "semgrep:scan".to_string(),
        cause: "semgrep binary missing".to_string(),
        what_failed: "semgrep:scan did not complete successfully".to_string(),
        artifacts_available: vec![RunArtifact {
            label: "input".to_string(),
            path: "/tmp/repo/.kuzushi/runs/r-1/input.json".to_string(),
            kind: "json".to_string(),
        }],
        missing_artifacts: vec!["findings.json".to_string()],
        allowed_proof_level: "artifact-review-only; runtime verification did not run".to_string(),
        next_files_or_artifacts_to_inspect: vec!["/tmp/repo/.kuzushi/runs/r-1/run.json".to_string()],
        recovery_options: vec!["Install semgrep and rerun semgrep:scan.".to_string()],
        fallback_prompt: "Continue the failed Kuzushi run for semgrep:scan.".to_string(),
        claims_forbidden: vec![
            "empirical proof claim".to_string(),
            "runtime proof claim".to_string(),
        ],
    };

    let prompt = agent_question_with_failure_context("what should I do next?", Some(&context));

    assert!(prompt.contains("Continue the failed Kuzushi run for semgrep:scan."));
    assert!(prompt.contains("failed_stage: semgrep:scan"));
    assert!(prompt.contains("allowed_proof_level: artifact-review-only"));
    assert!(prompt.contains("forbidden_claims: empirical proof claim, runtime proof claim"));
    assert!(!prompt.contains("validated"));
    assert!(prompt.ends_with("Operator question:\nwhat should I do next?"));
}

#[test]
fn question_is_unchanged_when_no_failure_context_is_pending() {
    assert_eq!(
        agent_question_with_failure_context("what changed?", None),
        "what changed?"
    );
}

#[test]
fn legacy_failure_context_lists_are_bounded_in_agent_prompt() {
    let context = FailureToLlmContext {
        failed_stage: "semgrep:scan".to_string(),
        cause: "scanner failed".to_string(),
        what_failed: "semgrep:scan failed".to_string(),
        artifacts_available: Vec::new(),
        missing_artifacts: numbered_items("missing", 15),
        allowed_proof_level: "artifact-review-only".to_string(),
        next_files_or_artifacts_to_inspect: numbered_items("next", 15),
        recovery_options: numbered_items("recovery", 15),
        fallback_prompt: "Continue the failed Kuzushi run.".to_string(),
        claims_forbidden: numbered_items("claim", 15),
    };

    let prompt = agent_question_with_failure_context("continue", Some(&context));

    assert!(prompt.contains("missing-11"));
    assert!(!prompt.contains("missing-12"));
    assert!(prompt.contains("+3 more"));
    assert!(!prompt.contains("claim-12"));
}

fn numbered_items(prefix: &str, count: usize) -> Vec<String> {
    (0..count)
        .map(|index| format!("{prefix}-{index}"))
        .collect()
}
