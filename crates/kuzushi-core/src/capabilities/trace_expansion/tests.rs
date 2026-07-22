use super::*;
use crate::findings::{Finding, Severity};
use crate::runtime::{AgentQueryRequest, AgentQueryResponse, AgentRuntime};
use crate::static_evidence::StaticEvidenceStore;
use anyhow::Result;
use serde_json::json;

#[test]
fn request_round_trips_camel_case_and_defaults_version() {
    let parsed: TraceExpansionRequest = serde_json::from_value(json!({
        "findingFingerprint": "fp-1",
        "currentPathNodeIds": ["n1", "n2"],
        "operatorInstruction": "follow the length across the ffi boundary"
    }))
    .unwrap();
    assert_eq!(parsed.version, TRACE_EXPANSION_CONTRACT_VERSION);
    assert_eq!(parsed.finding_fingerprint, "fp-1");
    assert_eq!(parsed.current_path_node_ids, vec!["n1", "n2"]);

    let value = serde_json::to_value(&parsed).unwrap();
    assert_eq!(value["findingFingerprint"], json!("fp-1"));
    assert_eq!(value["operatorInstruction"].as_str().is_some(), true);
    let round_tripped: TraceExpansionRequest = serde_json::from_value(value).unwrap();
    assert_eq!(round_tripped, parsed);
}

#[test]
fn contract_rejects_unknown_fields() {
    let request = serde_json::from_value::<TraceExpansionRequest>(json!({
        "findingFingerprint": "fp-1",
        "surprise": true
    }));
    assert!(request.is_err());

    let result = serde_json::from_value::<TraceExpansionResult>(json!({
        "findingFingerprint": "fp-1",
        "steps": [],
        "surprise": true
    }));
    assert!(result.is_err());
}

#[test]
fn result_clamps_steps_to_the_contract_cap() {
    let steps: Vec<TraceStep> = (0..(MAX_TRACE_EXPANSION_STEPS + 5))
        .map(|index| TraceStep {
            symbol: format!("hop_{index}"),
            file_path: "src/flow.rs".to_string(),
            line: index as u32,
            annotation: "copied".to_string(),
        })
        .collect();
    let result = TraceExpansionResult {
        version: TRACE_EXPANSION_CONTRACT_VERSION,
        finding_fingerprint: "fp-1".to_string(),
        steps,
        evidence_deltas: Vec::new(),
        open_questions: Vec::new(),
    }
    .clamped();
    assert_eq!(result.steps.len(), MAX_TRACE_EXPANSION_STEPS);
}

#[test]
fn appended_steps_read_back_in_order_with_operator_provenance() {
    let store = StaticEvidenceStore::open_in_memory().unwrap();
    let result = TraceExpansionResult {
        version: TRACE_EXPANSION_CONTRACT_VERSION,
        finding_fingerprint: "fp-trace".to_string(),
        steps: vec![
            step("read_frame", "src/net/frame.rs", 41, "length taken from wire header"),
            step("copy_payload", "src/net/copy.rs", 88, "memcpy with unchecked length"),
        ],
        evidence_deltas: vec!["length flows unchecked across frame boundary".to_string()],
        open_questions: Vec::new(),
    };

    let receipt = append_trace_expansion_evidence(&store, &result).unwrap();
    assert_eq!(receipt.node_ids.len(), 2);
    assert_eq!(receipt.edge_ids.len(), 1);

    let steps = list_operator_trace_steps(&store, "fp-trace").unwrap();
    assert_eq!(steps, result.steps);

    // Re-recording the same expansion is idempotent: stable ids, same rows.
    let second = append_trace_expansion_evidence(&store, &result).unwrap();
    assert_eq!(second, receipt);
    assert_eq!(list_operator_trace_steps(&store, "fp-trace").unwrap().len(), 2);

    // A different finding's trace stays invisible to this one.
    assert!(list_operator_trace_steps(&store, "fp-other")
        .unwrap()
        .is_empty());
}

#[test]
fn expansion_parses_structured_output_from_a_fake_runtime() {
    let runtime = CannedRuntime {
        structured: json!({
            "version": TRACE_EXPANSION_CONTRACT_VERSION,
            "findingFingerprint": "echoed-wrong",
            "steps": [
                {"symbol": "parse_header", "filePath": "src/parse.rs", "line": 10,
                 "annotation": "length decoded from attacker bytes"}
            ],
            "evidenceDeltas": ["header decode located"],
            "openQuestions": ["is the length re-checked in the writer?"]
        }),
    };
    let finding = trace_finding();
    let request = TraceExpansionRequest::new(finding.fingerprint.clone());

    let expansion = run_trace_expansion(
        &runtime,
        "test-model",
        std::path::Path::new("/tmp"),
        &finding,
        &request,
    )
    .unwrap();

    // The request fingerprint wins over whatever the agent echoed.
    assert_eq!(expansion.result.finding_fingerprint, finding.fingerprint);
    assert_eq!(expansion.result.steps.len(), 1);
    assert_eq!(expansion.result.steps[0].symbol, "parse_header");
    assert_eq!(expansion.result.open_questions.len(), 1);
}

fn step(symbol: &str, file_path: &str, line: u32, annotation: &str) -> TraceStep {
    TraceStep {
        symbol: symbol.to_string(),
        file_path: file_path.to_string(),
        line,
        annotation: annotation.to_string(),
    }
}

fn trace_finding() -> Finding {
    Finding::new_tool(
        "test",
        "rule/trace",
        "src/parse.rs",
        10,
        None,
        Severity::High,
        "attacker-controlled length flows to memcpy",
    )
}

struct CannedRuntime {
    structured: serde_json::Value,
}

impl AgentRuntime for CannedRuntime {
    fn query_blocking(&self, _request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        Ok(AgentQueryResponse {
            structured: Some(self.structured.clone()),
            ..Default::default()
        })
    }

    fn triage_finding_blocking(
        &self,
        _request: crate::runtime::TriageRequest,
    ) -> Result<crate::findings::TriageOutcome> {
        anyhow::bail!("triage is not part of the trace expansion fixture")
    }
}
