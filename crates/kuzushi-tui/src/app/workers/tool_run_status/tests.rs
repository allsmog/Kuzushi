use super::*;

fn question_request(run_id: &str) -> OperatorQuestionRequest {
    OperatorQuestionRequest {
        request_id: "question-private".to_string(),
        run_id: run_id.to_string(),
        questions: vec![OperatorQuestion {
            id: "scope".to_string(),
            header: "Scope".to_string(),
            prompt: "What should the scan include?".to_string(),
            options: vec![
                OperatorQuestionOption {
                    label: "Changed files".to_string(),
                    description: "Limit work to the current diff.".to_string(),
                    recommended: true,
                },
                OperatorQuestionOption {
                    label: "Repository".to_string(),
                    description: "Inspect the complete target.".to_string(),
                    recommended: false,
                },
            ],
        }],
        auto_resolution_ms: None,
    }
}

fn question_controls(
    request: &OperatorQuestionRequest,
    generation: WorkerGeneration,
) -> [OperatorQuestionControl; 3] {
    [
        OperatorQuestionControl::SnoozeAutoResolution {
            request_id: request.request_id.clone(),
            run_id: request.run_id.clone(),
            generation,
        },
        OperatorQuestionControl::Resolve {
            resolution: OperatorQuestionResolution {
                request_id: request.request_id.clone(),
                kind: OperatorQuestionResolutionKind::Submitted,
                answers: Vec::new(),
            },
            run_id: request.run_id.clone(),
            generation,
        },
        OperatorQuestionControl::Cancel {
            request_id: request.request_id.clone(),
            run_id: request.run_id.clone(),
            generation,
        },
    ]
}

#[test]
fn older_operator_question_generation_cannot_control_matching_run_and_request() {
    let request = question_request("shared-run");
    let current = WorkerGeneration::new(7);
    for control in question_controls(&request, WorkerGeneration::new(6)) {
        assert!(matches!(
            question_signal(control, &request, current),
            QuestionSignal::Wait
        ));
    }

    let [snooze, resolve, cancel] = question_controls(&request, current);
    assert!(matches!(
        question_signal(snooze, &request, current),
        QuestionSignal::Snooze
    ));
    assert!(matches!(
        question_signal(resolve, &request, current),
        QuestionSignal::Resolve(resolution)
            if resolution.kind == OperatorQuestionResolutionKind::Submitted
    ));
    assert!(matches!(
        question_signal(cancel, &request, current),
        QuestionSignal::Resolve(resolution)
            if resolution.kind == OperatorQuestionResolutionKind::Canceled
    ));
}

#[test]
fn operator_questions_are_available_to_non_anthropic_shell_models() {
    let request = root_shell_agent_request(
        "openai-codex:gpt-5.5".to_string(),
        PathBuf::from("/target"),
        agent_system_prompt(),
        "inspect this".to_string(),
    );

    assert_eq!(request.model, "openai-codex:gpt-5.5");
    assert_eq!(request.max_steps, MAX_AGENT_STEPS);
    assert_eq!(request.tools.len(), 1);
    assert_eq!(request.tools[0].name, REQUEST_USER_INPUT_TOOL);
    assert!(request
        .system_prompt
        .contains("may call request_user_input"));
}

#[test]
fn planner_questions_continue_the_same_turn_instead_of_serializing_ask_changes() {
    assert!(PLAN_SYSTEM_PROMPT.contains("call request_user_input"));
    assert!(PLAN_SYSTEM_PROMPT.contains("continue this same planning turn"));
    assert!(PLAN_SYSTEM_PROMPT.contains("Do not emit an ask change"));
    assert!(!PLAN_SYSTEM_PROMPT.contains(r#"{"kind": "ask"#));

    let request = root_shell_agent_request(
        "openai-codex:gpt-5.5".to_string(),
        PathBuf::from("/target"),
        PLAN_SYSTEM_PROMPT.to_string(),
        "plan a scan".to_string(),
    );
    assert_eq!(request.max_steps, MAX_AGENT_STEPS);
    assert_eq!(request.tools[0].name, REQUEST_USER_INPUT_TOOL);
}

#[test]
fn persisted_freeform_resolution_records_presence_but_not_raw_text() {
    let target = tempfile::tempdir().unwrap();
    let run_id = "agent-private-answer";
    let request = question_request(run_id);
    let secret_answer = "scan the unreleased payment adapter";
    let resolution = OperatorQuestionResolution {
        request_id: request.request_id.clone(),
        kind: OperatorQuestionResolutionKind::Submitted,
        answers: vec![OperatorQuestionAnswer::Freeform {
            question_id: "scope".to_string(),
            text: secret_answer.to_string(),
        }],
    };

    persist_operator_resolution(target.path(), run_id, &request, &resolution).unwrap();

    let read = kuzushi_core::run_artifacts::load_run_events(target.path(), run_id).unwrap();
    assert_eq!(read.malformed_lines, 0);
    let interaction = read.events[0].interaction.as_ref().unwrap();
    assert_eq!(interaction.request_id, "question-private");
    assert_eq!(interaction.question_id, "scope");
    assert_eq!(interaction.predefined_label, None);
    assert_eq!(interaction.resolution, "submitted");
    assert!(interaction.freeform_supplied);
    assert!(!serde_json::to_string(&read.events)
        .unwrap()
        .contains(secret_answer));
}

#[test]
fn credential_route_persists_only_the_route_and_never_an_answer() {
    let target = tempfile::tempdir().unwrap();
    let run_id = "agent-credential-route";
    let mut request = question_request(run_id);
    request.questions[0].id = "credentials".to_string();
    request.questions[0].header = "Auth".to_string();
    request.questions[0].prompt = "Paste the provider API key".to_string();
    let resolution = OperatorQuestionResolution::routed_to_setup(request.request_id.clone());

    persist_operator_resolution(target.path(), run_id, &request, &resolution).unwrap();

    let read = kuzushi_core::run_artifacts::load_run_events(target.path(), run_id).unwrap();
    let interaction = read.events[0].interaction.as_ref().unwrap();
    assert_eq!(interaction.resolution, "routed_to_setup");
    assert_eq!(interaction.predefined_label, None);
    assert!(!interaction.freeform_supplied);
    assert!(resolution.answers.is_empty());
}
