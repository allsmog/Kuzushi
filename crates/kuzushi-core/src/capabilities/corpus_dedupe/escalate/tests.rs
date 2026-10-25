use super::*;
use crate::runtime::{AgentQueryResponse, TriageRequest};

struct NoQueryRuntime;

impl AgentRuntime for NoQueryRuntime {
    fn query_blocking(&self, _: AgentQueryRequest) -> Result<AgentQueryResponse> {
        panic!("unavailable confirmation must not query")
    }

    fn triage_finding_blocking(&self, _: TriageRequest) -> Result<crate::findings::TriageOutcome> {
        panic!("confirmation must not invoke triage")
    }
}

fn findings() -> Vec<Finding> {
    ["one", "two"]
        .into_iter()
        .map(|rule| {
            Finding::new_tool(
                "owned",
                rule,
                " source.txt ",
                1,
                None,
                crate::findings::Severity::Info,
                "Owned metadata",
            )
        })
        .collect()
}

fn group(findings: &[Finding]) -> DuplicateGroup {
    DuplicateGroup {
        canonical_fingerprint: findings[0].fingerprint.clone(),
        duplicate_fingerprints: vec![findings[1].fingerprint.clone()],
        root_cause_summary: "Owned duplicate proposal".into(),
        confidence: 0.5,
    }
}

#[test]
fn unavailable_or_oversized_confirmation_is_dropped_without_inference() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::write(root.join(" source.txt "), "Owned text\n").unwrap();
    let findings = findings();
    let index = crate::capabilities::corpus_dedupe::fingerprint_index(&findings);
    for value in [
        json!({"maxConfirmationBytes":1}),
        json!({"maxJudgePromptBytes":1}),
    ] {
        let options = DedupeOptions::from_input(&value).unwrap();
        let judged = JudgedGroups {
            groups: vec![group(&findings)],
            dropped: BTreeMap::new(),
        };
        let mut cost = RuntimeCostReport::known(crate::runtime::RuntimeCost::ZERO);
        let confirmed = escalate_low_confidence(
            &NoQueryRuntime,
            "openai-codex:gpt-5.5",
            &root,
            judged,
            &index,
            &options,
            &mut cost,
        )
        .unwrap();
        assert!(confirmed.groups.is_empty());
        assert_eq!(confirmed.escalated, 1);
        assert_eq!(
            confirmed.dropped["confirmation_source_or_prompt_unavailable"],
            1
        );
    }
}

#[test]
fn requests_have_no_tools_one_turn_and_current_source_disclosure() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::write(root.join(" source.txt "), "Owned literal source\n").unwrap();
    let findings = findings();
    let index = crate::capabilities::corpus_dedupe::fingerprint_index(&findings);
    let mut sources = SourceInputs::new(&root, 256);
    let confirmation = escalation_request(
        "openai-codex:gpt-5.5",
        &root,
        &group(&findings),
        &index,
        &mut sources,
        16384,
    )
    .unwrap();
    assert!(confirmation.prompt.contains("Owned literal source"));
    assert!(confirmation.prompt.contains("may differ from historical"));
    let judge = crate::capabilities::corpus_dedupe::dedupe_prompt::dedupe_request(
        "openai-codex:gpt-5.5",
        &root,
        &findings,
        16384,
    )
    .unwrap();
    for request in [confirmation, judge] {
        assert!(request.tool_policy.tools.is_empty());
        assert_ne!(request.tool_policy.profile, "default");
        assert_eq!(request.runtime_options.unwrap().max_model_turns, Some(1));
    }
}

#[test]
fn missing_citation_refuses_instead_of_sending_an_empty_excerpt() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::write(root.join(" source.txt "), "one line\n").unwrap();
    let mut finding = findings().remove(0);
    finding.start_line = 50;
    let mut sources = SourceInputs::new(&root, 256);
    assert!(member_excerpt(&mut sources, &finding)
        .unwrap_err()
        .to_string()
        .contains("citation unavailable"));
}
