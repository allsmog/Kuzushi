use super::*;

#[test]
fn terminal_status_samples_cancellation_at_settlement_time() {
    let canceled = ScanCancellation::default();
    assert_eq!(
        terminal_status_after_cancellation(
            &canceled,
            kuzushi_core::run_lifecycle::RunItemStatus::Failed
        ),
        kuzushi_core::run_lifecycle::RunItemStatus::Failed
    );
    canceled.cancel();
    assert_eq!(
        terminal_status_after_cancellation(
            &canceled,
            kuzushi_core::run_lifecycle::RunItemStatus::Completed
        ),
        kuzushi_core::run_lifecycle::RunItemStatus::Canceled
    );

    let interrupted = ScanCancellation::default();
    interrupted.interrupt();
    assert_eq!(
        terminal_status_after_cancellation(
            &interrupted,
            kuzushi_core::run_lifecycle::RunItemStatus::Failed
        ),
        kuzushi_core::run_lifecycle::RunItemStatus::Interrupted
    );
}

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

fn operator_question_observation(
    target: &std::path::Path,
    run_id: &str,
) -> kuzushi_core::run_lifecycle::RunObservationHandle {
    let observation = kuzushi_core::run_lifecycle::RunObservationHandle::jsonl(target, run_id)
        .unwrap()
        .start_root_task("Answer the operator request")
        .unwrap();
    mark_root_task_running(&observation).unwrap();
    observation
}

#[test]
fn persisted_freeform_resolution_uses_typed_receipts_without_raw_text() {
    let target = tempfile::tempdir().unwrap();
    let run_id = "agent-private-answer";
    let request = question_request(run_id);
    let observation = operator_question_observation(target.path(), run_id);
    let observed = persist_operator_questions(&observation, &request).unwrap();
    let secret_answer = "scan the unreleased payment adapter";
    let resolution = OperatorQuestionResolution {
        request_id: request.request_id.clone(),
        kind: OperatorQuestionResolutionKind::Submitted,
        answers: vec![OperatorQuestionAnswer::Freeform {
            question_id: "scope".to_string(),
            text: secret_answer.to_string(),
        }],
    };

    persist_operator_decisions(&observation, &observed, &resolution).unwrap();

    let projection = kuzushi_core::run_lifecycle::load_run_projection(target.path(), run_id)
        .unwrap()
        .projection;
    assert!(projection.timeline.iter().any(|envelope| matches!(
        envelope.item,
        kuzushi_core::run_lifecycle::RunItemV1::OperatorQuestion { .. }
    )));
    assert!(projection.timeline.iter().any(|envelope| matches!(
        envelope.item,
        kuzushi_core::run_lifecycle::RunItemV1::OperatorDecision {
            decision: kuzushi_core::run_lifecycle::OperatorDecisionValue::ProvidedFreeform,
            ..
        }
    )));
    let items =
        std::fs::read_to_string(kuzushi_core::run_dir(target.path(), run_id).join("items.jsonl"))
            .unwrap();
    assert!(!items.contains(secret_answer));
}

#[test]
fn credential_route_persists_a_typed_deferred_decision() {
    let target = tempfile::tempdir().unwrap();
    let run_id = "agent-credential-route";
    let mut request = question_request(run_id);
    request.questions[0].id = "credentials".to_string();
    request.questions[0].header = "Auth".to_string();
    request.questions[0].prompt = "Paste the provider API key".to_string();
    let resolution = OperatorQuestionResolution::routed_to_setup(request.request_id.clone());
    let observation = operator_question_observation(target.path(), run_id);
    let observed = persist_operator_questions(&observation, &request).unwrap();

    persist_operator_decisions(&observation, &observed, &resolution).unwrap();

    let projection = kuzushi_core::run_lifecycle::load_run_projection(target.path(), run_id)
        .unwrap()
        .projection;
    assert!(projection.timeline.iter().any(|envelope| matches!(
        envelope.item,
        kuzushi_core::run_lifecycle::RunItemV1::OperatorDecision {
            decision: kuzushi_core::run_lifecycle::OperatorDecisionValue::Deferred,
            ..
        }
    )));
    assert!(resolution.answers.is_empty());
}

#[test]
fn operator_decision_requires_the_exact_observed_choice_identity() {
    let request = question_request("run-choice-identity");
    let question = observed_operator_question(&request, &request.questions[0], 0);
    let answer = OperatorQuestionAnswer::Predefined {
        question_id: "scope".to_string(),
        choice_id: "choice-stale".to_string(),
        label: "Changed files".to_string(),
    };

    let error = operator_decision_value(
        &question,
        Some(&answer),
        OperatorQuestionResolutionKind::Submitted,
    )
    .unwrap_err();

    assert!(error.to_string().contains("unknown choice identity"));
}

#[test]
fn safe_model_summary_uses_the_coalescible_writer_lane() {
    let target = tempfile::tempdir().unwrap();
    let run_id = "agent-summary-settlement";
    let observation =
        kuzushi_core::run_lifecycle::RunObservationHandle::jsonl(target.path(), run_id)
            .unwrap()
            .start_root_task("Answer the operator request")
            .unwrap();
    mark_root_task_running(&observation).unwrap();

    emit_safe_model_summary(&observation, "model-backed workflow completed").unwrap();
    observation.flush().unwrap();

    let projection = kuzushi_core::run_lifecycle::load_run_projection(target.path(), run_id)
        .unwrap()
        .projection;
    assert!(projection.timeline.iter().any(|envelope| matches!(
        envelope.item,
        kuzushi_core::run_lifecycle::RunItemV1::SafeReasoningSummary { .. }
    )));
}
